use bolero_engine::{rng::RngEngine, Engine, Never, SliceTestInput, TargetLocation, Test};
use bolero_generator::driver::DriverMode;
use libtest_mimic::{run_tests, Arguments, FormatSetting, Outcome, Test as LibTest};
use std::{io::Read, path::PathBuf};

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

    fn sub_dir(&self, name: &str) -> PathBuf {
        let mut fuzz_target_path = self
            .location
            .abs_path()
            .expect("could not resolve target location");
        fuzz_target_path.pop();
        fuzz_target_path.push(name);
        fuzz_target_path
    }

    fn file_tests(&self, sub_dir: &'static str) -> impl Iterator<Item = LibTest<TestData>> {
        std::fs::read_dir(self.sub_dir(sub_dir))
            .ok()
            .into_iter()
            .map(move |dir| {
                dir.filter_map(Result::ok)
                    .map(|item| item.path())
                    .filter(|path| path.is_file())
                    .filter(|path| !path.file_name().unwrap().to_str().unwrap().starts_with('.'))
                    .map(move |path| LibTest {
                        name: format!(
                            "{}/{}",
                            sub_dir,
                            path.file_stem().unwrap().to_str().unwrap()
                        ),
                        kind: "".into(),
                        is_ignored: false,
                        is_bench: false,
                        data: TestData::FileTest(FileTest { path }),
                    })
            })
            .flatten()
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
        bolero_engine::panic::set_hook();

        let driver_mode = self.driver_mode;
        let mut input = vec![];
        let testfn = &mut |data: &TestData| {
            bolero_engine::panic::forward_panic(false);
            input.clear();
            data.read_into(&mut input);

            test.test(&mut SliceTestInput::new(&input, driver_mode))
                .map_err(|_| {
                    let failure = test
                        .shrink(input.clone(), data.seed(), driver_mode)
                        .expect("test should fail");

                    format!("{:#}", failure)
                })
        };

        // `run_tests` only accepts `Fn` instead of `FnMut`
        // convert the function to a dynamic FnMut and drop the lifetime
        static mut TESTFN: Option<&mut dyn FnMut(&TestData) -> Result<bool, String>> = None;

        unsafe {
            TESTFN = Some(std::mem::transmute(
                testfn as &mut dyn FnMut(&TestData) -> Result<bool, String>,
            ));
        }

        let mut entries = vec![];

        entries.extend(self.file_tests("corpus"));
        entries.extend(self.file_tests("crashes"));

        #[cfg(feature = "rand")]
        {
            use rand::{rngs::StdRng, RngCore, SeedableRng};

            let rng_info = RngEngine::default();
            let mut seed_rng = StdRng::seed_from_u64(rng_info.seed);

            let seeds = (0..rng_info.iterations).scan(rng_info.seed, |state, _index| {
                let seed = *state;
                *state = seed_rng.next_u64();
                Some(seed)
            });

            for seed in seeds {
                entries.push(LibTest {
                    name: format!("randomized[seed={}]", seed),
                    kind: "".into(),
                    is_ignored: false,
                    is_bench: false,
                    data: TestData::RngTest(RngTest {
                        seed,
                        max_len: rng_info.max_len,
                    }),
                })
            }
        }

        let mut arguments = Arguments::from_args();

        if arguments.format.is_none() {
            arguments.format = Some(FormatSetting::Terse);
        }

        run_tests(&arguments, entries, |config| {
            let testfn = unsafe { (TESTFN.as_mut().expect("uninitialized test function")) };
            if let Err(err) = testfn(&config.data) {
                Outcome::Failed { msg: Some(err) }
            } else {
                Outcome::Passed
            }
        })
        .exit();
    }
}

enum TestData {
    FileTest(FileTest),
    #[cfg(feature = "rand")]
    RngTest(RngTest),
}

impl TestData {
    fn read_into(&self, input: &mut Vec<u8>) {
        match self {
            TestData::FileTest(t) => t.read_into(input),
            #[cfg(feature = "rand")]
            TestData::RngTest(t) => t.read_into(input),
        }
    }

    fn seed(&self) -> Option<u64> {
        match self {
            TestData::FileTest(_) => None,
            #[cfg(feature = "rand")]
            TestData::RngTest(t) => Some(t.seed),
        }
    }
}

struct FileTest {
    path: PathBuf,
}

impl FileTest {
    fn read_into(&self, input: &mut Vec<u8>) {
        std::fs::File::open(&self.path)
            .unwrap()
            .read_to_end(input)
            .unwrap();
    }
}

#[cfg(feature = "rand")]
struct RngTest {
    seed: u64,
    max_len: usize,
}

#[cfg(feature = "rand")]
impl RngTest {
    fn read_into(&self, input: &mut Vec<u8>) {
        use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};
        let mut rng = StdRng::seed_from_u64(self.seed);
        let len = rng.gen_range(0, self.max_len);
        input.resize(len, 0);
        rng.fill_bytes(input);
    }
}
