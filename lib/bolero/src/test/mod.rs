#![cfg_attr(fuzzing_random, allow(dead_code))]

use bolero_engine::{
    driver::{self, exhaustive, object::Object},
    rng, Engine, Failure, Seed, TargetLocation, Test,
};
use core::{fmt, mem::size_of, time::Duration};
use std::path::PathBuf;

type ExhastiveDriver = Box<Object<exhaustive::Driver>>;

mod input;
mod outcome;
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
    data: input::Test,
}

impl fmt::Display for NamedTest {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let input::Test::Rng(test) = &self.data {
            write!(f, "[BOLERO_RANDOM_SEED={}]", test.seed)
        } else {
            write!(f, "{}", self.name)
        }
    }
}

impl From<input::RngTest> for NamedTest {
    #[inline]
    fn from(value: input::RngTest) -> Self {
        Self {
            name: String::new(),
            data: input::Test::Rng(value),
        }
    }
}

impl TestEngine {
    #[allow(dead_code)]
    pub fn new(location: TargetLocation) -> Self {
        Self {
            location,
            rng_cfg: Default::default(),
        }
    }

    pub fn with_test_time(&mut self, test_time: Duration) -> &mut Self {
        self.rng_cfg.test_time = self.rng_cfg.test_time.or(Some(test_time));
        self
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
                        data: input::Test::File(input::FileTest { path }),
                    })
            })
    }

    fn seed_tests(&self) -> impl Iterator<Item = input::RngTest> {
        self.rng_cfg
            .seed
            .into_iter()
            .map(move |seed| input::RngTest { seed })
    }

    fn rng_tests(&self) -> impl Iterator<Item = input::RngTest> {
        use rand::{rngs::StdRng, RngCore, SeedableRng};

        let iterations = self.rng_cfg.iterations_or_default();
        // use StdRng for high entropy seeds
        let mut seed_rng = StdRng::from_os_rng();

        (0..iterations).map(move |_| {
            let mut seed = [0; size_of::<Seed>()];
            seed_rng.fill_bytes(&mut seed);
            let seed = Seed::from_le_bytes(seed);
            input::RngTest { seed }
        })
    }

    #[cfg(fuzzing_random)]
    fn tests(&self) -> impl Iterator<Item = NamedTest> {
        self.seed_tests()
            .map(|t| t.into())
            .chain(self.rng_tests().map(|t| t.into()))
    }

    #[cfg(not(fuzzing_random))]
    fn tests(&self) -> impl Iterator<Item = NamedTest> {
        self.seed_tests()
            .map(|t| t.into())
            .chain(self.file_tests(["crashes"].iter().cloned()))
            .chain(self.file_tests(["afl_state", "crashes"].iter().cloned()))
            .chain(self.file_tests(["afl_state", "hangs"].iter().cloned()))
            .chain(self.file_tests(["corpus"].iter().cloned()))
            .chain(self.file_tests(["afl_state", "queue"].iter().cloned()))
            .chain(self.rng_tests().map(|t| t.into()))
    }

    fn run_with_value<T>(self, test: T, options: driver::Options) -> bolero_engine::Never
    where
        T: Test,
        T::Value: core::fmt::Debug,
    {
        if options.exhaustive() {
            let mut buffer = vec![];

            let testfn = |mut driver: Box<Object<exhaustive::Driver>>, test: &mut T| {
                let mut input = input::ExhastiveInput {
                    driver: &mut driver,
                    buffer: &mut buffer,
                };

                let result = match test.test(&mut input) {
                    Ok(is_valid) => Ok(is_valid),
                    Err(error) => {
                        // restart the driver to replay what was selected
                        input.driver.replay();
                        let input = test.generate_value(&mut input);
                        let error = Failure {
                            seed: None,
                            error,
                            input,
                        };
                        Err(error.to_string())
                    }
                };

                (driver, result)
            };

            return self.run_exhaustive(test, testfn, options);
        }

        let file_options = options.clone();
        let rng_options = options;

        let file_options = &file_options;
        let rng_options = &rng_options;

        let mut buffer = vec![];
        let mut cache = driver::cache::Cache::default();
        let testfn = |test: &mut T, data: &input::Test| {
            buffer.clear();
            match data {
                input::Test::File(file) => {
                    file.read_into(&mut buffer);

                    let mut input = input::Bytes::new(&buffer, file_options);
                    test.test(&mut input).map_err(|error| {
                        let shrunken = test.shrink(buffer.clone(), data.seed(), file_options);

                        if let Some(shrunken) = shrunken {
                            format!("{shrunken:#}")
                        } else {
                            format!(
                                "{:#}",
                                Failure {
                                    seed: data.seed(),
                                    error,
                                    input: buffer.clone()
                                }
                            )
                        }
                    })
                }
                input::Test::Rng(conf) => {
                    let mut input = conf.input(&mut buffer, &mut cache, rng_options);
                    test.test(&mut input).map_err(|error| {
                        let shrunken = if rng_options.shrink_time_or_default().is_zero() {
                            None
                        } else {
                            // reseed the input and buffer the rng for shrinking
                            let mut input = conf.buffered_input(&mut buffer, rng_options);
                            let _ = test.generate_value(&mut input);

                            test.shrink(buffer.clone(), data.seed(), rng_options)
                        };

                        if let Some(shrunken) = shrunken {
                            format!("{shrunken:#}")
                        } else {
                            buffer.clear();
                            let mut input = conf.input(&mut buffer, &mut cache, rng_options);
                            let input = test.generate_value(&mut input);
                            format!(
                                "{:#}",
                                Failure {
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

        self.run_tests(test, testfn)
    }

    #[cfg(feature = "std")]
    fn run_with_scope<T, R>(self, test: T, options: driver::Options)
    where
        T: FnMut() -> R + core::panic::RefUnwindSafe,
        R: bolero_engine::IntoResult,
    {
        if options.exhaustive() {
            let testfn = |driver: ExhastiveDriver, test: &mut T| {
                let (driver, result) = bolero_engine::any::run(driver, test);
                let result = result.map_err(|error| {
                    Failure {
                        seed: None,
                        error,
                        input: (),
                    }
                    .to_string()
                });
                (driver, result)
            };

            return self.run_exhaustive(test, testfn, options);
        }

        let file_options = options.clone();
        let rng_options = options;

        let file_options = &file_options;
        let rng_options = &rng_options;

        let mut buffer = vec![];
        // TODO
        // let mut cache = driver::cache::Cache::default();
        let file_driver = bolero_engine::driver::bytes::Driver::new(vec![], file_options);
        let file_driver = bolero_engine::driver::object::Object(file_driver);
        let file_driver = Box::new(file_driver);
        let mut file_driver = Some(file_driver);

        let testfn = |test: &mut T, data: &input::Test| {
            buffer.clear();
            match data {
                input::Test::File(file) => {
                    let mut driver = file_driver.take().unwrap();

                    let mut buf = core::mem::take(&mut buffer);
                    file.read_into(&mut buf);
                    driver.reset(buf, file_options);
                    let (mut driver, result) = bolero_engine::any::run(driver, test);
                    buffer = driver.reset(vec![], file_options);
                    file_driver = Some(driver);

                    // TODO shrinking

                    result.map_err(|error| {
                        Failure {
                            seed: None,
                            error,
                            input: (), // TODO figure out a better input to show
                        }
                        .to_string()
                    })
                }
                input::Test::Rng(conf) => {
                    let seed = conf.seed;
                    let driver = conf.driver(rng_options);
                    let driver = Box::new(Object(driver));
                    let (_driver, result) = bolero_engine::any::run(driver, test);

                    // TODO shrinking

                    result.map_err(|error| {
                        Failure {
                            seed: Some(seed),
                            error,
                            input: (), // TODO figure out a better input to show
                        }
                        .to_string()
                    })
                }
            }
        };

        self.run_tests(test, testfn)
    }

    fn run_tests<S, T>(mut self, mut state: S, mut testfn: T)
    where
        T: FnMut(&mut S, &input::Test) -> Result<bool, String>,
    {
        // if we're fuzzing with cargo-bolero and the iteration count isn't specified
        // then go forever
        if cfg!(fuzzing_random) && self.rng_cfg.iterations.is_none() {
            self.rng_cfg.iterations = Some(usize::MAX);
        }

        let tests = self.tests();

        let start_time = std::time::Instant::now();
        let test_time = if cfg!(fuzzing_random) {
            self.rng_cfg.test_time
        } else {
            Some(self.rng_cfg.test_time_or_default()).filter(|v| *v < Duration::MAX)
        };

        let mut report = report::Report::default();
        if cfg!(fuzzing_random) {
            report.spawn_timer();
        }

        let mut outcome = outcome::Outcome::new(&self.location, start_time);

        bolero_engine::panic::set_hook();
        bolero_engine::panic::forward_panic(false);

        for input in tests {
            if let Some(test_time) = test_time {
                if start_time.elapsed() > test_time {
                    outcome.on_exit(outcome::ExitReason::MaxDurationExceeded {
                        limit: test_time,
                        default: self.rng_cfg.test_time.is_none(),
                    });
                    break;
                }
            }

            outcome.on_named_test(&input.data);

            match testfn(&mut state, &input.data) {
                Ok(is_valid) => {
                    report.on_result(is_valid);
                }
                Err(err) => {
                    bolero_engine::panic::forward_panic(true);
                    outcome.on_exit(outcome::ExitReason::TestFailure);
                    drop(outcome);
                    eprintln!("{err}");
                    panic!("test failed");
                }
            }
        }
    }

    fn run_exhaustive<S, F>(self, mut state: S, mut testfn: F, options: driver::Options)
    where
        F: FnMut(ExhastiveDriver, &mut S) -> (ExhastiveDriver, Result<bool, String>),
    {
        bolero_engine::panic::set_hook();
        bolero_engine::panic::forward_panic(false);

        let driver = exhaustive::Driver::new(&options);
        let mut driver = Box::new(Object(driver));
        let test_time = self.rng_cfg.test_time;
        let start_time = std::time::Instant::now();

        let mut report = report::Report::default();
        // when running exhaustive tests, it's nice to have the progress displayed
        report.spawn_timer();

        let mut outcome = outcome::Outcome::new(&self.location, start_time);

        while driver.step().is_continue() {
            if let Some(test_time) = test_time {
                if start_time.elapsed() > test_time {
                    outcome.on_exit(outcome::ExitReason::MaxDurationExceeded {
                        limit: test_time,
                        default: false,
                    });
                    break;
                }
            }

            outcome.on_exhaustive_input();

            let (drvr, result) = testfn(driver, &mut state);
            driver = drvr;

            match result {
                Ok(is_valid) => {
                    report.on_estimate(driver.estimate());
                    report.on_result(is_valid);
                }
                Err(error) => {
                    bolero_engine::panic::forward_panic(true);
                    outcome.on_exit(outcome::ExitReason::TestFailure);
                    drop(outcome);
                    eprintln!("{error}");
                    panic!("test failed");
                }
            }
        }
    }
}

impl<T> Engine<T> for TestEngine
where
    T: Test,
    T::Value: core::fmt::Debug,
{
    type Output = ();

    fn run(self, test: T, options: driver::Options) -> Self::Output {
        self.run_with_value(test, options);
        bolero_engine::panic::forward_panic(true);
    }
}

#[cfg(feature = "std")]
impl bolero_engine::ScopedEngine for TestEngine {
    type Output = ();

    fn run<F, R>(self, test: F, options: driver::Options) -> Self::Output
    where
        F: FnMut() -> R + core::panic::RefUnwindSafe,
        R: bolero_engine::IntoResult,
    {
        self.run_with_scope(test, options);
        bolero_engine::panic::forward_panic(true);
    }
}
