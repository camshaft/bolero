use crate::{driver, panic, ByteSliceTestInput, Engine, TargetLocation, Test};
use core::{fmt::Debug, time::Duration};
use rand::{Rng, RngCore, SeedableRng};
use std::time::Instant;

pub use rand_xoshiro::Xoshiro256PlusPlus as Recommended;

#[derive(Clone, Copy, Debug)]
pub struct Options {
    pub test_time: Option<Duration>,
    pub iterations: Option<usize>,
    pub max_len: Option<usize>,
    pub seed: Option<u64>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            test_time: get_var("BOLERO_RANDOM_TEST_TIME_MS").map(Duration::from_millis),
            iterations: get_var("BOLERO_RANDOM_ITERATIONS"),
            max_len: get_var("BOLERO_RANDOM_MAX_LEN"),
            seed: get_var("BOLERO_RANDOM_SEED"),
        }
    }
}

impl Options {
    pub fn test_time_or_default(&self) -> Duration {
        self.test_time.unwrap_or_else(|| {
            if self.iterations.is_some() {
                Duration::MAX
            } else {
                Duration::from_secs(1)
            }
        })
    }

    pub fn iterations_or_default(&self) -> usize {
        self.iterations.unwrap_or(usize::MAX)
    }

    pub fn max_len_or_default(&self) -> usize {
        self.max_len.unwrap_or(if cfg!(miri) { 1024 } else { 4096 })
    }

    pub fn seed_or_rand(&self) -> u64 {
        self.seed.unwrap_or_else(|| rand::thread_rng().next_u64())
    }
}

/// Test engine implementation using a RNG.
///
/// The inputs will only be derived from the `seed` field.
/// As such, the quality of the inputs may not be high
/// enough to find edge cases.
#[derive(Clone)]
pub struct RngEngine {
    pub test_time: Duration,
    pub iterations: usize,
    pub max_len: usize,
    pub seed: u64,
}

impl Default for RngEngine {
    fn default() -> Self {
        Options::default().into()
    }
}

impl From<Options> for RngEngine {
    fn from(options: Options) -> Self {
        Self {
            test_time: options.test_time_or_default(),
            iterations: options.iterations_or_default(),
            max_len: options.max_len_or_default(),
            seed: options.seed_or_rand(),
        }
    }
}

impl RngEngine {
    /// Create a new `RngEngine`
    pub fn new(location: TargetLocation) -> Self {
        let _ = location;
        Self::default()
    }

    /// Set the test time
    pub fn with_test_time(self, test_time: Duration) -> Self {
        Self { test_time, ..self }
    }

    /// Set the number of test iterations
    pub fn with_iterations(self, iterations: usize) -> Self {
        Self { iterations, ..self }
    }

    /// Set the maximum length of a test input
    pub fn with_max_len(self, max_len: usize) -> Self {
        Self { max_len, ..self }
    }

    /// Set the seed for the RNG implementation
    pub fn with_seed(self, seed: u64) -> Self {
        Self { seed, ..self }
    }
}

impl<T: Test> Engine<T> for RngEngine
where
    T::Value: 'static + Debug + Send,
{
    type Output = ();

    fn run(self, mut test: T, options: driver::Options) -> Self::Output {
        panic::set_hook();

        let mut state = RngState::new(self.seed, self.max_len, options);

        let start_time = Instant::now();
        let mut valid = 0;
        let mut invalid = 0;
        while valid < self.iterations && start_time.elapsed() < self.test_time {
            match test.test(&mut state.next_input()) {
                Ok(true) => {
                    valid += 1;
                    continue;
                }
                Ok(false) => {
                    invalid += 1;
                    if invalid > self.iterations * 2 {
                        break;
                    }
                }
                #[cfg(not(miri))]
                Err(_) => {
                    let failure = test
                        .shrink(
                            core::mem::take(&mut state.buffer),
                            Some(self.seed),
                            &state.options,
                        )
                        .expect("test should fail");

                    eprintln!("{}", failure);

                    std::panic::resume_unwind(Box::new(failure));
                }
                #[cfg(miri)]
                Err(failure) => {
                    // don't shrink in Miri execution
                    eprintln!("{}", failure);
                    std::panic::resume_unwind(Box::new(failure));
                }
            }
        }
        if invalid > valid * 2 {
            panic!(
                concat!(
                    "Test input generator had too many rejected inputs after {} iterations:\n",
                    "         valid: {}\n",
                    "       invalid: {}\n",
                    "\n",
                    "Try reconfiguring the input generator to produce more valid inputs",
                ),
                valid + invalid,
                valid,
                invalid,
            );
        }
    }
}

struct RngState {
    rng: Recommended,
    max_len: usize,
    options: driver::Options,
    buffer: Vec<u8>,
}

impl RngState {
    fn new(seed: u64, max_len: usize, options: driver::Options) -> Self {
        Self {
            rng: SeedableRng::seed_from_u64(seed),
            max_len,
            options,
            buffer: vec![],
        }
    }

    fn next_input(&mut self) -> ByteSliceTestInput {
        let len = self.rng.gen_range(0..self.max_len);
        self.buffer.clear();
        self.buffer.resize(len, 0);
        self.rng.fill_bytes(&mut self.buffer);
        ByteSliceTestInput::new(&self.buffer, &self.options)
    }
}

fn get_var<T: std::str::FromStr>(name: &str) -> Option<T> {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<T>().ok())
}
