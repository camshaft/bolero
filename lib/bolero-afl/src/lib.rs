//! afl plugin for bolero
//!
//! This crate should not be used directly. Instead, use `bolero`.

#[doc(hidden)]
#[cfg(any(test, all(feature = "lib", fuzzing_afl)))]
pub mod fuzzer {
    use bolero_engine::{driver, input, panic, Engine, Never, ScopedEngine, TargetLocation, Test};
    use std::io::Read;

    extern "C" {
        // from the afl-llvm-rt
        fn __afl_persistent_loop(counter: usize) -> isize;
        fn __afl_manual_init();
    }

    #[used]
    static PERSIST_MARKER: &str = "##SIG_AFL_PERSISTENT##\0";

    #[used]
    static DEFERED_MARKER: &str = "##SIG_AFL_DEFER_FORKSRV##\0";

    #[derive(Debug, Default)]
    pub struct AflEngine {}

    impl AflEngine {
        pub fn new(_location: TargetLocation) -> Self {
            Self::default()
        }
    }

    impl<T: Test> Engine<T> for AflEngine
    where
        T::Value: core::fmt::Debug,
    {
        type Output = Never;

        fn run(self, mut test: T, options: driver::Options) -> Self::Output {
            panic::set_hook();

            let mut ctx = bolero_engine::TestRunContext::new(
                bolero_engine::EngineKind::Afl,
                bolero_engine::TestInput::default(),
                0,
                bolero_engine::RunPhase::Normal,
            );
            // AFL does not shrink inputs within bolero — it transitions straight from
            // Normal to Failure on a failing input.
            ctx.shrink_enabled = false;
            let _ctx_guard = bolero_engine::test_context::enter(ctx);

            let mut input = AflInput::new(options);

            unsafe {
                __afl_manual_init();
            }

            let mut iteration = 0u64;
            while unsafe { __afl_persistent_loop(1000) } != 0 {
                // Clear any on_failure callback from the previous iteration, then reset
                // the per-iteration context fields before running this input.
                bolero_engine::test_context::clear_on_failure();
                bolero_engine::test_context::update(|ctx| {
                    ctx.iteration = iteration;
                    ctx.run_phase = bolero_engine::RunPhase::Normal;
                });
                iteration += 1;

                // `test_input()` reads the next input from stdin, so run it in a scope
                // that ends its borrow before any replay.
                let failed = {
                    let mut test_input = input.test_input();
                    test.test(&mut test_input).is_err()
                };
                if failed {
                    // No shrinking: set the Failure phase and replay the same input
                    // (from the buffered bytes, not stdin) so the application can
                    // capture diagnostic output, then invoke the failure callback.
                    bolero_engine::test_context::update(|ctx| {
                        ctx.run_phase = bolero_engine::RunPhase::Failure;
                    });
                    let mut replay = input::Bytes::new(&input.input, &input.options);
                    let _ = test.test(&mut replay);
                    bolero_engine::test_context::invoke_on_failure();
                    std::process::abort();
                }
            }

            std::process::exit(0);
        }
    }

    impl ScopedEngine for AflEngine {
        type Output = Never;

        fn run<F, R>(self, mut test: F, options: driver::Options) -> Self::Output
        where
            F: FnMut() -> R + core::panic::RefUnwindSafe,
            R: bolero_engine::IntoResult,
        {
            panic::set_hook();

            let mut ctx = bolero_engine::TestRunContext::new(
                bolero_engine::EngineKind::Afl,
                bolero_engine::TestInput::default(),
                0,
                bolero_engine::RunPhase::Normal,
            );
            // AFL does not shrink inputs within bolero.
            ctx.shrink_enabled = false;
            let _ctx_guard = bolero_engine::test_context::enter(ctx);

            // extend the lifetime of the bytes so it can be stored in local storage
            let driver = bolero_engine::driver::bytes::Driver::new(vec![], &options);
            let driver = bolero_engine::driver::object::Object(driver);
            let mut driver = Box::new(driver);

            let mut input = AflInput::new(options);

            unsafe {
                __afl_manual_init();
            }

            let mut iteration = 0u64;
            while unsafe { __afl_persistent_loop(1000) } != 0 {
                // Clear any on_failure callback from the previous iteration, then reset
                // the per-iteration context fields before running this input.
                bolero_engine::test_context::clear_on_failure();
                bolero_engine::test_context::update(|ctx| {
                    ctx.iteration = iteration;
                    ctx.run_phase = bolero_engine::RunPhase::Normal;
                });
                iteration += 1;

                input.reset();
                let bytes = core::mem::take(&mut input.input);
                let tmp = driver.reset(bytes, &input.options);
                let (drv, result) = bolero_engine::any::run(driver, &mut test);
                driver = drv;
                input.input = driver.reset(tmp, &input.options);

                if result.is_err() {
                    // No shrinking: set the Failure phase and replay the same input so
                    // the application can capture diagnostic output, then invoke the
                    // failure callback before aborting.
                    bolero_engine::test_context::update(|ctx| {
                        ctx.run_phase = bolero_engine::RunPhase::Failure;
                    });
                    let bytes = core::mem::take(&mut input.input);
                    let tmp = driver.reset(bytes, &input.options);
                    let (drv, _) = bolero_engine::any::run(driver, &mut test);
                    driver = drv;
                    input.input = driver.reset(tmp, &input.options);

                    bolero_engine::test_context::invoke_on_failure();
                    std::process::abort();
                }
            }

            std::process::exit(0);
        }
    }

    #[derive(Debug)]
    pub struct AflInput {
        options: driver::Options,
        input: Vec<u8>,
    }

    impl AflInput {
        fn new(options: driver::Options) -> Self {
            Self {
                options,
                input: vec![],
            }
        }

        fn reset(&mut self) {
            self.input.clear();
            std::io::stdin()
                .read_to_end(&mut self.input)
                .expect("could not read next input");
        }

        fn test_input(&mut self) -> input::Bytes {
            self.reset();
            input::Bytes::new(&self.input, &self.options)
        }
    }
}

#[doc(hidden)]
#[cfg(all(feature = "lib", fuzzing_afl))]
pub use fuzzer::*;

#[doc(hidden)]
#[cfg(feature = "bin")]
pub mod bin {
    use std::{
        ffi::CString,
        os::raw::{c_char, c_int},
    };

    extern "C" {
        // entrypoint for afl
        pub fn afl_fuzz_main(a: c_int, b: *const *const c_char) -> c_int;
    }

    /// Should only be used by `cargo-bolero`
    ///
    /// # Safety
    ///
    /// Use `cargo-bolero`
    pub unsafe fn exec<Args: Iterator<Item = String>>(args: Args) {
        // create a vector of zero terminated strings
        let args = args
            .map(|arg| CString::new(arg).unwrap())
            .collect::<Vec<_>>();

        // convert the strings to raw pointers
        let c_args = args
            .iter()
            .map(|arg| arg.as_ptr())
            .chain(Some(core::ptr::null())) // add a null pointer to the end
            .collect::<Vec<_>>();

        let status = afl_fuzz_main(args.len() as c_int, c_args.as_ptr());
        if status != 0 {
            std::process::exit(status);
        }
    }
}

#[doc(hidden)]
#[cfg(feature = "bin")]
pub use bin::*;
