use bolero_engine::{rng::RngEngine, ByteSliceTestInput, Engine, Never, TargetLocation, Test};
use bolero_generator::driver::DriverMode;
use core::iter::empty;
use libtest_mimic::{run_tests, Arguments, FormatSetting, Outcome, Test as LibTest};
use std::path::PathBuf;

mod input;
use input::*;

/// Engine implementation which mimics Rust's default test
/// harness. By default, the test inputs will include any present
/// `corpus` and `crashes` files, as well as generating
#[derive(Debug)]
pub struct TestEngine {
    location: TargetLocation,
    driver_mode: Option<DriverMode>,
}

impl TestEngine {
    #[allow(dead_code)]
    pub fn new(location: TargetLocation) -> Self {
        Self {
            location,
            driver_mode: None,
        }
    }

    fn sub_dir<'a, D: Iterator<Item = &'a str>>(&self, dirs: D) -> PathBuf {
        let mut fuzz_target_path = self
            .location
            .work_dir()
            .expect("could not resolve target work dir");

        fuzz_target_path.extend(dirs);

        fuzz_target_path
    }

    fn file_tests<'a, D: Iterator<Item = &'a str> + std::panic::UnwindSafe>(
        &self,
        sub_dirs: D,
    ) -> impl Iterator<Item = LibTest<TestInput>> {
        std::fs::read_dir(self.sub_dir(sub_dirs))
            .ok()
            .into_iter()
            .map(move |dir| {
                dir.filter_map(Result::ok)
                    .map(|item| item.path())
                    .filter(|path| path.is_file())
                    .filter(|path| !path.file_name().unwrap().to_str().unwrap().starts_with('.'))
                    .map(move |path| LibTest {
                        name: format!("{}", path.display()),
                        kind: "".into(),
                        is_ignored: false,
                        is_bench: false,
                        data: TestInput::FileTest(FileTest { path }),
                    })
            })
            .flatten()
    }

    #[cfg(feature = "rand")]
    fn rng_tests(&self) -> impl Iterator<Item = LibTest<TestInput>> {
        use rand::{rngs::StdRng, RngCore, SeedableRng};

        let rng_info = RngEngine::default();
        let mut seed_rng = StdRng::seed_from_u64(rng_info.seed);

        let test_name = self.location.module_path;

        (0..rng_info.iterations)
            .scan(rng_info.seed, move |state, _index| {
                let seed = *state;
                *state = seed_rng.next_u64();
                Some(seed)
            })
            .map(move |seed| LibTest {
                name: format!("{} [seed={}]", test_name, seed),
                kind: "".into(),
                is_ignored: false,
                is_bench: false,
                data: TestInput::RngTest(RngTest {
                    seed,
                    max_len: rng_info.max_len,
                }),
            })
    }

    #[cfg(not(feature = "rand"))]
    fn rng_tests(&self) -> impl Iterator<Item = LibTest<TestInput>> {
        empty()
    }

    fn tests(&self) -> Vec<LibTest<TestInput>> {
        empty()
            .chain(self.file_tests(["corpus"].iter().cloned()))
            .chain(self.file_tests(["crashes"].iter().cloned()))
            .chain(self.file_tests(["afl_state", "hangs"].iter().cloned()))
            .chain(self.file_tests(["afl_state", "queue"].iter().cloned()))
            .chain(self.file_tests(["afl_state", "crashes"].iter().cloned()))
            .chain(self.rng_tests())
            .collect()
    }

    /// Use the libtest_mimic harness
    fn libtest_mimic(self, testfn: &mut dyn FnMut(&TestInput) -> Result<bool, String>) -> Never {
        // `run_tests` only accepts `Fn` instead of `FnMut`
        // convert the function to a dynamic FnMut and drop the lifetime
        static mut TESTFN: Option<&mut dyn FnMut(&TestInput) -> Result<bool, String>> = None;

        unsafe {
            TESTFN = Some(std::mem::transmute(
                testfn as &mut dyn FnMut(&TestInput) -> Result<bool, String>,
            ));
        }

        let mut arguments = Arguments::from_args();

        if arguments.format.is_none() {
            arguments.format = Some(FormatSetting::Terse);
        }

        let tests = self.tests();

        bolero_engine::panic::set_hook();
        bolero_engine::panic::forward_panic(true);

        let result = run_tests(&arguments, tests, |config| {
            let testfn = unsafe { TESTFN.as_mut().expect("uninitialized test function") };
            let result = testfn(&config.data);

            // show progress for miri
            if cfg!(miri) {
                use std::io::{stderr, Write};
                write!(stderr(), ".").unwrap();
            }

            if let Err(err) = result {
                Outcome::Failed { msg: Some(err) }
            } else {
                Outcome::Passed
            }
        });

        result.exit();
    }

    /// Use the libtest harness
    fn libtest(self, testfn: &mut dyn FnMut(&TestInput) -> Result<bool, String>) -> Never {
        let tests = self.tests();

        bolero_engine::panic::set_hook();
        bolero_engine::panic::forward_panic(false);

        for test in tests {
            // show progress for miri
            if cfg!(miri) {
                use std::io::{stderr, Write};
                write!(stderr(), ".").unwrap();
            }

            if let Err(err) = testfn(&test.data) {
                bolero_engine::panic::forward_panic(true);
                eprintln!("{}", err);
                panic!("test failed");
            }
        }
    }
}

impl<T: Test> Engine<T> for TestEngine
where
    T::Value: core::fmt::Debug,
{
    type Output = Never;

    fn set_driver_mode(&mut self, mode: DriverMode) {
        self.driver_mode = Some(mode);
    }

    fn run(self, mut test: T) -> Self::Output {
        let driver_mode = self.driver_mode;
        let mut input = vec![];
        let mut testfn = &mut |data: &TestInput| {
            input.clear();
            data.read_into(&mut input);

            test.test(&mut ByteSliceTestInput::new(&input, driver_mode))
                .map_err(|_| {
                    let failure = test
                        .shrink(input.clone(), data.seed(), driver_mode)
                        .expect("test should fail");

                    format!("{:#}", failure)
                })
        };

        if self.location.is_harnessed() {
            self.libtest(&mut testfn)
        } else {
            self.libtest_mimic(&mut testfn)
        }
    }
}
