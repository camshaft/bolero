#![cfg_attr(fuzzing_random, allow(dead_code))]

use bolero_engine::{driver, rng, Engine, Failure, Seed, TargetLocation, Test};
use core::{fmt, mem::size_of, time::Duration};
use std::path::PathBuf;

mod input;

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
        let mut seed_rng = StdRng::from_entropy();

        (0..iterations).map(move |_| {
            let mut seed = [0; size_of::<Seed>()];
            seed_rng.fill_bytes(&mut seed);
            let seed = Seed::from_le_bytes(seed);
            input::RngTest { seed }
        })
    }

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

        let mut report = report::Report::default();
        report.spawn_timer();

        if self.rng_cfg.iterations.is_none() {
            self.rng_cfg.iterations = Some(usize::MAX);
        }

        let start_time = std::time::Instant::now();
        let test_time = self.rng_cfg.test_time;

        let mut buffer = vec![];
        let mut cache = bolero_generator::driver::cache::Cache::default();
        let mut testfn = |conf: &input::RngTest| {
            let mut input = conf.input(&mut buffer, &mut cache, options);
            test.test(&mut input).map_err(|error| {
                let seed = Some(conf.seed);
                // reseed the input and buffer the rng for shrinking
                let mut input = conf.buffered_input(&mut buffer, options);
                let _ = test.generate_value(&mut input);

                let input = input::RngReplayInput {
                    buffer: &mut buffer.clone(),
                };
                let shrunken = test.shrink(input, seed, options);

                if let Some(shrunken) = shrunken {
                    format!("{:#}", shrunken)
                } else {
                    buffer.clear();
                    let mut input = conf.input(&mut buffer, &mut cache, options);
                    let input = test.generate_value(&mut input);
                    format!("{:#}", Failure { seed, error, input })
                }
            })
        };

        for input in self.rng_tests() {
            if let Some(test_time) = test_time {
                if start_time.elapsed() > test_time {
                    break;
                }
            }

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
        let file_options = options.clone();
        let rng_options = options;

        let file_options = &file_options;
        let rng_options = &rng_options;

        let mut buffer = vec![];
        let mut cache = driver::cache::Cache::default();
        let mut testfn = |data: &input::Test| {
            buffer.clear();
            match data {
                input::Test::File(file) => {
                    file.read_into(&mut buffer);

                    let mut input = input::Bytes::new(&buffer, file_options);
                    test.test(&mut input).map_err(|error| {
                        let shrunken = test.shrink(buffer.clone(), data.seed(), file_options);

                        if let Some(shrunken) = shrunken {
                            format!("{:#}", shrunken)
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
                            format!("{:#}", shrunken)
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

        let tests = self.tests();

        bolero_engine::panic::set_hook();
        bolero_engine::panic::forward_panic(false);

        let start_time = std::time::Instant::now();
        let test_time = self.rng_cfg.test_time_or_default();
        for test in tests {
            if start_time.elapsed() > test_time {
                break;
            }

            progress();

            if let Err(err) = testfn(&test.data) {
                bolero_engine::panic::forward_panic(true);
                eprintln!("{}", err);
                panic!("test failed: {}", test);
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
