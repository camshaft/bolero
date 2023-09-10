use bolero_engine::{
    rng::RngEngine, test_failure::TestFailure, ByteSliceTestInput, Engine, Never, TargetLocation,
    Test,
};
use bolero_generator::driver::DriverMode;
use core::{iter::empty, time::Duration};
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
    shrink_time: Option<Duration>,
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
            driver_mode: None,
            shrink_time: None,
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

    fn rng_tests(&self) -> impl Iterator<Item = NamedTest> {
        use rand::{rngs::StdRng, RngCore, SeedableRng};

        let rng_info = RngEngine::default();
        let mut seed_rng = StdRng::seed_from_u64(rng_info.seed);

        (0..rng_info.iterations)
            .scan(rng_info.seed, move |state, _index| {
                let seed = *state;
                *state = seed_rng.next_u64();
                Some(seed)
            })
            .map(move |seed| NamedTest {
                name: format!("[BOLERO_RANDOM_SEED={}]", seed),
                data: TestInput::RngTest(RngTest {
                    seed,
                    max_len: rng_info.max_len,
                }),
            })
    }

    fn tests(&self) -> Vec<NamedTest> {
        empty()
            .chain(self.file_tests(["crashes"].iter().cloned()))
            .chain(self.file_tests(["afl_state", "crashes"].iter().cloned()))
            .chain(self.file_tests(["afl_state", "hangs"].iter().cloned()))
            .chain(self.file_tests(["corpus"].iter().cloned()))
            .chain(self.file_tests(["afl_state", "queue"].iter().cloned()))
            .chain(self.rng_tests())
            .collect()
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

impl<T: Test> Engine<T> for TestEngine
where
    T::Value: core::fmt::Debug,
{
    type Output = Never;

    fn set_driver_mode(&mut self, mode: DriverMode) {
        self.driver_mode = Some(mode);
    }

    fn set_shrink_time(&mut self, shrink_time: Duration) {
        self.shrink_time = Some(shrink_time);
    }

    fn run(self, mut test: T) -> Self::Output {
        let driver_mode = self.driver_mode;
        let shrink_time = self.shrink_time;
        let mut buffer = vec![];
        let mut testfn = |data: &TestInput| {
            buffer.clear();
            match data {
                TestInput::FileTest(file) => {
                    file.read_into(&mut buffer);

                    let mut input = ByteSliceTestInput::new(&buffer, driver_mode);
                    test.test(&mut input).map_err(|error| {
                        let shrunken =
                            test.shrink(buffer.clone(), data.seed(), driver_mode, shrink_time);

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
                    let mut input = conf.input(&mut buffer);
                    test.test(&mut input).map_err(|error| {
                        // reseed the input and buffer the rng for shrinking
                        let mut input = conf.buffered_input(&mut buffer);
                        let _ = test.generate_value(&mut input);

                        let shrunken = test.shrink(
                            buffer.clone(),
                            data.seed(),
                            Some(DriverMode::Forced),
                            shrink_time,
                        );

                        if let Some(shrunken) = shrunken {
                            format!("{:#}", shrunken)
                        } else {
                            buffer.clear();
                            let mut input = conf.input(&mut buffer);
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
    }
}
