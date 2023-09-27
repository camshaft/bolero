#![cfg_attr(fuzzing_random, allow(dead_code))]

use bolero_engine::{driver, rng, test_failure::TestFailure, Engine, TargetLocation, Test};
use core::iter::empty;
use std::path::PathBuf;

mod input;
use input::*;

#[cfg(any(fuzzing_random, test))]
mod report;

/// Engine implementation which mimics Rust's default test
/// harness. By default, the test inputs will include any present
/// `corpus` and `crashes` files, as well as generating
#[derive(Debug)]
pub struct TestEngine {
    location: TargetLocation,
    rng_cfg: rng::Options,
}

struct NamedTest {
    name: String,
    data: TestInput,
}

impl TestEngine {
    #[allow(dead_code)]
    pub fn new(location: TargetLocation) -> Self {
        Self {
            location,
            rng_cfg: Default::default(),
        }
    }

    pub fn with_iterations(&mut self, iterations: usize) -> &mut Self {
        self.rng_cfg.iterations = self.rng_cfg.iterations.or(Some(iterations));
        self
    }

    pub fn with_max_len(&mut self, max_len: usize) -> &mut Self {
        self.rng_cfg.max_len = self.rng_cfg.max_len.or(Some(max_len));
        self
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
    ) -> impl Iterator<Item = NamedTest> {
        std::fs::read_dir(self.sub_dir(sub_dirs))
            .ok()
            .into_iter()
            .flat_map(move |dir| {
                dir.filter_map(Result::ok)
                    .map(|item| item.path())
                    .filter(|path| path.is_file())
                    .filter(|path| !path.file_name().unwrap().to_str().unwrap().starts_with('.'))
                    .map(move |path| NamedTest {
                        name: format!("{}", path.display()),
                        data: TestInput::FileTest(FileTest { path }),
                    })
            })
    }

    fn rng_tests(&self) -> impl Iterator<Item = RngTest> {
        use rand::{rngs::StdRng, RngCore, SeedableRng};

        let iterations = self.rng_cfg.iterations_or_default();
        let max_len = self.rng_cfg.max_len_or_default();
        let seed = self.rng_cfg.seed_or_rand();
        let mut seed_rng = StdRng::seed_from_u64(seed);

        (0..iterations)
            .scan(seed, move |state, _index| {
                let seed = *state;
                *state = seed_rng.next_u64();
                Some(seed)
            })
            .map(move |seed| input::RngTest { seed, max_len })
    }

    fn tests(&self) -> Vec<NamedTest> {
        let rng_tests = self.rng_tests().map(move |test| NamedTest {
            name: format!("[BOLERO_RANDOM_SEED={}]", test.seed),
            data: TestInput::RngTest(test),
        });

        empty()
            .chain(self.file_tests(["crashes"].iter().cloned()))
            .chain(self.file_tests(["afl_state", "crashes"].iter().cloned()))
            .chain(self.file_tests(["afl_state", "hangs"].iter().cloned()))
            .chain(self.file_tests(["corpus"].iter().cloned()))
            .chain(self.file_tests(["afl_state", "queue"].iter().cloned()))
            .chain(rng_tests)
            .collect()
    }

    #[cfg(any(fuzzing_random, test))]
    #[cfg_attr(not(fuzzing_random), allow(dead_code))]
    fn run_fuzzer<T>(mut self, mut test: T, options: driver::Options) -> bolero_engine::Never
    where
        T: Test,
        T::Value: core::fmt::Debug,
    {
        bolero_engine::panic::set_hook();
        bolero_engine::panic::forward_panic(false);

        let options = &options;

        let mut buffer = vec![];
        let mut testfn = |conf: &input::RngTest| {
            let mut input = conf.input(&mut buffer, options);
            test.test(&mut input).map_err(|error| {
                let seed = Some(conf.seed);
                // reseed the input and buffer the rng for shrinking
                let mut input = conf.buffered_input(&mut buffer, options);
                let _ = test.generate_value(&mut input);

                let shrunken = test.shrink(buffer.clone(), seed, options);

                if let Some(shrunken) = shrunken {
                    format!("{:#}", shrunken)
                } else {
                    buffer.clear();
                    let mut input = conf.input(&mut buffer, options);
                    let input = test.generate_value(&mut input);
                    format!("{:#}", TestFailure { seed, error, input })
                }
            })
        };

        let mut report = report::Report::default();
        report.spawn_timer();

        let inputs = {
            if self.rng_cfg.iterations.is_none() {
                self.rng_cfg.iterations = Some(usize::MAX);
            }
            self.rng_tests()
        };

        for input in inputs {
            match testfn(&input) {
                Ok(is_valid) => {
                    report.on_result(is_valid);
                }
                Err(err) => {
                    bolero_engine::panic::forward_panic(true);
                    eprintln!("{}", err);
                    panic!("test failed");
                }
            }
        }
    }

    #[cfg(not(fuzzing_random))]
    fn run_tests<T>(self, mut test: T, options: driver::Options)
    where
        T: Test,
        T::Value: core::fmt::Debug,
    {
        let mut file_options = options.clone();
        let mut rng_options = options.clone();

        // set the driver mode to direct for file replays since they were likely generated with
        // fuzzers
        if file_options.driver_mode().is_none() {
            file_options.set_driver_mode(crate::DriverMode::Direct);
        }

        // set the driver mode to forced so we increase the likelihood of valid generators
        if rng_options.driver_mode().is_none() {
            rng_options.set_driver_mode(crate::DriverMode::Forced);
        }

        let file_options = &file_options;
        let rng_options = &rng_options;

        let mut buffer = vec![];
        let mut testfn = |data: &TestInput| {
            buffer.clear();
            match data {
                TestInput::FileTest(file) => {
                    file.read_into(&mut buffer);

                    let mut input = bolero_engine::ByteSliceTestInput::new(&buffer, file_options);
                    test.test(&mut input).map_err(|error| {
                        let shrunken = test.shrink(buffer.clone(), data.seed(), file_options);

                        if let Some(shrunken) = shrunken {
                            format!("{:#}", shrunken)
                        } else {
                            format!(
                                "{:#}",
                                TestFailure {
                                    seed: data.seed(),
                                    error,
                                    input: buffer.clone()
                                }
                            )
                        }
                    })
                }
                TestInput::RngTest(conf) => {
                    let mut input = conf.input(&mut buffer, rng_options);
                    test.test(&mut input).map_err(|error| {
                        // reseed the input and buffer the rng for shrinking
                        let mut input = conf.buffered_input(&mut buffer, rng_options);
                        let _ = test.generate_value(&mut input);

                        let shrunken = test.shrink(buffer.clone(), data.seed(), rng_options);

                        if let Some(shrunken) = shrunken {
                            format!("{:#}", shrunken)
                        } else {
                            buffer.clear();
                            let mut input = conf.input(&mut buffer, rng_options);
                            let input = test.generate_value(&mut input);
                            format!(
                                "{:#}",
                                TestFailure {
                                    seed: data.seed(),
                                    error,
                                    input
                                }
                            )
                        }
                    })
                }
            }
        };

        let tests = self.tests();

        bolero_engine::panic::set_hook();
        bolero_engine::panic::forward_panic(false);

        for test in tests {
            progress();

            if let Err(err) = testfn(&test.data) {
                bolero_engine::panic::forward_panic(true);
                eprintln!("{}", err);
                panic!("test failed: {:?}", test.name);
            }
        }

        fn progress() {
            if cfg!(miri) {
                use std::io::{stderr, Write};

                // miri doesn't capture explicit writes to stderr
                #[allow(clippy::explicit_write)]
                let _ = write!(stderr(), ".");
            }
        }
    }
}

impl<T> Engine<T> for TestEngine
where
    T: Test,
    T::Value: core::fmt::Debug,
{
    #[cfg(fuzzing_random)]
    type Output = bolero_engine::Never;
    #[cfg(not(fuzzing_random))]
    type Output = ();

    #[cfg(fuzzing_random)]
    fn run(self, test: T, options: driver::Options) -> Self::Output {
        self.run_fuzzer(test, options)
    }

    #[cfg(not(fuzzing_random))]
    fn run(self, test: T, options: driver::Options) -> Self::Output {
        self.run_tests(test, options)
    }
}
