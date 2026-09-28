//! libfuzzer plugin for bolero
//!
//! This crate should not be used directly. Instead, use `bolero`.

#[doc(hidden)]
#[cfg(any(test, all(feature = "lib", fuzzing_libfuzzer)))]
pub mod fuzzer {
    use bolero_engine::{
        driver, input, panic, Engine, Failure, Never, ScopedEngine, TargetLocation, Test,
    };
    use core::time::Duration;
    use std::{
        ffi::CString,
        os::raw::{c_char, c_int},
        sync::atomic,
    };

    extern "C" {
        // entrypoint for libfuzzer
        pub fn LLVMFuzzerStartTest(a: c_int, b: *const *const c_char) -> c_int;
    }

    type TestFn<'a> = &'a mut dyn FnMut(&[u8]);

    static mut TESTFN: Option<TestFn> = None;

    #[derive(Debug, Default)]
    pub struct LibFuzzerEngine {}

    impl LibFuzzerEngine {
        pub fn new(_location: TargetLocation) -> Self {
            Self::default()
        }
    }

    impl<T: Test> Engine<T> for LibFuzzerEngine
    where
        T::Value: core::fmt::Debug,
    {
        type Output = Never;

        fn run(self, mut test: T, options: driver::Options) -> Self::Output {
            panic::set_hook();
            panic::forward_panic(false);

            let mut ctx = bolero_engine::TestRunContext::new(
                bolero_engine::EngineKind::LibFuzzer,
                bolero_engine::TestInput::default(),
                0,
                bolero_engine::RunPhase::Normal,
            );
            // The non-scoped libfuzzer path shrinks failing inputs (see `test.shrink`
            // below), so report shrinking as enabled unless the shrink budget is zero.
            ctx.shrink_enabled = !options.shrink_time_or_default().is_zero();
            let _ctx_guard = bolero_engine::test_context::enter(ctx);

            let options = &options;
            let mut cache = driver::cache::Cache::default();
            let mut report = GeneratorReport::default();
            report.spawn_timer();

            let mut iteration = 0u64;
            start(&mut |slice: &[u8]| {
                // Clear any on_failure callback from the previous iteration, then reset
                // the per-iteration context fields before running this input.
                bolero_engine::test_context::clear_on_failure();
                bolero_engine::test_context::update(|ctx| {
                    ctx.iteration = iteration;
                    ctx.run_phase = bolero_engine::RunPhase::Normal;
                });
                iteration += 1;

                let mut input = input::cache::Bytes::new(slice, options, &mut cache);

                match test.test(&mut input) {
                    Ok(is_valid) => {
                        report.on_result(is_valid);
                    }
                    Err(error) => {
                        eprintln!("test failed; shrinking input...");

                        let shrunken = test.shrink(slice.to_vec(), None, options);

                        if let Some(shrunken) = shrunken {
                            // shrink.rs already ran the final confirmed-failure execution
                            // with RunPhase::Failure set
                            eprintln!("{shrunken:#}");
                        } else {
                            // Shrinking was skipped or made no progress.
                            // Set failure phase and re-run the original input so the
                            // application can capture diagnostic output.
                            bolero_engine::test_context::update(|ctx| {
                                ctx.run_phase = bolero_engine::RunPhase::Failure;
                            });
                            let mut replay = input::cache::Bytes::new(slice, options, &mut cache);
                            let _ = test.test(&mut replay);
                            let input = input::Bytes::new(slice, options);
                            eprintln!(
                                "{:#}",
                                Failure {
                                    seed: None,
                                    error,
                                    input
                                }
                            );
                        }

                        bolero_engine::test_context::invoke_on_failure();
                        std::process::abort();
                    }
                }
            })
        }
    }

    impl ScopedEngine for LibFuzzerEngine {
        type Output = Never;

        fn run<F, R>(self, mut test: F, options: driver::Options) -> Self::Output
        where
            F: FnMut() -> R + core::panic::RefUnwindSafe,
            R: bolero_engine::IntoResult,
        {
            panic::set_hook();
            panic::forward_panic(false);

            let mut ctx = bolero_engine::TestRunContext::new(
                bolero_engine::EngineKind::LibFuzzer,
                bolero_engine::TestInput::default(),
                0,
                bolero_engine::RunPhase::Normal,
            );
            // The scoped libfuzzer path does not shrink (see the caching TODO below),
            // so it transitions straight from Normal to Failure on a failing input.
            ctx.shrink_enabled = false;
            let _ctx_guard = bolero_engine::test_context::enter(ctx);

            let options = &options;
            // TODO implement caching
            // let mut cache = driver::cache::Cache::default();
            let mut report = GeneratorReport::default();
            report.spawn_timer();

            // extend the lifetime of the bytes so it can be stored in local storage
            let driver = bolero_engine::driver::bytes::Driver::new(&[][..], options);
            let driver = bolero_engine::driver::object::Object(driver);
            let driver = Box::new(driver);
            let mut driver = Some(driver);

            let mut iteration = 0u64;
            start(&mut |slice: &[u8]| {
                // extend the lifetime of the slice so it can be stored in TLS
                let input: &'static [u8] = unsafe { core::mem::transmute::<&[u8], &[u8]>(slice) };

                // Clear any on_failure callback from the previous iteration, then reset
                // the per-iteration context fields before running this input.
                bolero_engine::test_context::clear_on_failure();
                bolero_engine::test_context::update(|ctx| {
                    ctx.iteration = iteration;
                    ctx.run_phase = bolero_engine::RunPhase::Normal;
                });
                iteration += 1;

                let mut drv = driver.take().unwrap();
                drv.reset(input, options);
                let (drv, result) = bolero_engine::any::run(drv, &mut test);
                driver = Some(drv);

                match result {
                    Ok(is_valid) => {
                        report.on_result(is_valid);
                    }
                    Err(error) => {
                        // No shrinking in scoped mode: set the Failure phase and replay
                        // the same input so the application can capture diagnostic
                        // output, then invoke the failure callback before aborting.
                        bolero_engine::test_context::update(|ctx| {
                            ctx.run_phase = bolero_engine::RunPhase::Failure;
                        });
                        let mut drv = driver.take().unwrap();
                        drv.reset(input, options);
                        let (drv, _) = bolero_engine::any::run(drv, &mut test);
                        driver = Some(drv);

                        eprintln!(
                            "{:#}",
                            Failure {
                                seed: None,
                                error,
                                input: (),
                            }
                        );

                        bolero_engine::test_context::invoke_on_failure();
                        std::process::abort();
                    }
                }
            });
        }
    }

    #[derive(Default)]
    struct GeneratorReport {
        total_runs: u64,
        window_runs: u64,
        total_valid: u64,
        window_valid: u64,
        should_print: std::sync::Arc<atomic::AtomicBool>,
    }

    impl GeneratorReport {
        pub fn spawn_timer(&self) {
            let should_print = self.should_print.clone();
            std::thread::spawn(move || {
                while std::sync::Arc::strong_count(&should_print) > 1 {
                    std::thread::sleep(Duration::from_secs(1));
                    should_print.store(true, atomic::Ordering::Relaxed);
                }
            });
        }

        pub fn on_result(&mut self, is_valid: bool) {
            self.window_runs += 1;
            if is_valid {
                self.window_valid += 1;
            }

            // nothing to report
            if self.window_runs == self.window_valid {
                return;
            }

            if !self.should_print.swap(false, atomic::Ordering::Relaxed) {
                return;
            }

            self.total_runs += self.window_runs;
            self.total_valid += self.window_valid;

            let total_perc = self.total_valid as f32 / self.total_runs as f32 * 100.0;
            let window_perc = self.window_valid as f32 / self.window_runs as f32 * 100.0;
            println!(
                "#{}\tGENERATE\tvalid: {} ({:.2}%) valid/s: {} ({:.2}%)",
                self.total_runs, self.total_valid, total_perc, self.window_valid, window_perc,
            );
            self.window_runs = 0;
            self.window_valid = 0;
        }
    }

    fn start<F: FnMut(&[u8])>(run_one_test: &mut F) -> Never {
        unsafe {
            TESTFN = Some(std::mem::transmute::<TestFn, TestFn>(
                run_one_test as &mut dyn FnMut(&[u8]),
            ));
        }

        // Libfuzzer can generate multiple jobs that can make the binary recurse.
        // Still, let’s limit recursion depth to some reasonable amount.
        let recursion_level = std::env::var("__BOLERO_LIBFUZZER_RECURSE")
            .as_deref()
            .unwrap_or("0")
            .parse()
            .unwrap_or(usize::MAX);

        if recursion_level > 10 {
            eprintln!("LOOPING BINARY");
            std::process::exit(1);
        }

        std::env::set_var(
            "__BOLERO_LIBFUZZER_RECURSE",
            (recursion_level + 1).to_string(),
        );

        // create a vector of NULL terminated strings
        let args = std::env::args()
            .next()
            .as_deref()
            .into_iter()
            .chain(
                std::env::var("BOLERO_LIBFUZZER_ARGS")
                    .expect("missing libfuzzer args")
                    .split(' '),
            )
            .map(|arg| CString::new(arg).unwrap())
            .collect::<Vec<_>>();

        // convert the strings to raw pointers
        let c_args = args
            .iter()
            .map(|arg| arg.as_ptr())
            .chain(Some(core::ptr::null())) // add a null pointer to the end
            .collect::<Vec<_>>();

        let res = unsafe { LLVMFuzzerStartTest(args.len() as c_int, c_args.as_ptr()) };

        std::process::exit(res);
    }

    #[doc(hidden)]
    #[no_mangle]
    pub unsafe extern "C" fn LLVMFuzzerTestOneInput(data: *const u8, size: usize) -> i32 {
        let data_slice = std::slice::from_raw_parts(data, size);
        (TESTFN.as_mut().expect("uninitialized test function"))(data_slice);
        0
    }

    #[doc(hidden)]
    #[no_mangle]
    pub unsafe extern "C" fn LLVMFuzzerInitialize(
        _argc: *const isize,
        _argv: *const *const *const u8,
    ) -> isize {
        0
    }
}

#[doc(hidden)]
#[cfg(all(feature = "lib", fuzzing_libfuzzer))]
pub use fuzzer::*;
