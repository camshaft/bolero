use crate::{panic, ByteSliceTestInput, Engine, TargetLocation, Test};
use bolero_generator::driver::DriverMode;
use bolero_instrument::Instrument;
use core::{fmt::Debug, mem::replace};
use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};
use std::panic::RefUnwindSafe;

/// Test engine implementation using a RNG.
///
/// The inputs will only be derived from the `seed` field.
/// As such, the quality of the inputs may not be high
/// enough to find edge cases.
#[derive(Copy, Clone, PartialEq)]
pub struct RngEngine {
    pub iterations: usize,
    pub max_len: usize,
    pub seed: u64,
    pub driver_mode: Option<DriverMode>,
}

impl Default for RngEngine {
    fn default() -> Self {
        let iterations = get_var("BOLERO_RANDOM_ITERATIONS").unwrap_or(1000);
        let max_len = get_var("BOLERO_RANDOM_MAX_LEN").unwrap_or(4096);
        let seed = get_var("BOLERO_RANDOM_SEED").unwrap_or_else(|| rand::thread_rng().next_u64());

        Self {
            iterations,
            max_len,
            seed,
            driver_mode: None,
        }
    }
}

impl RngEngine {
    /// Create a new `RngEngine`
    pub fn new(location: TargetLocation) -> Self {
        let _ = location;
        Self::default()
    }

    /// Set the number of test iterations
    pub fn with_iterations(self, iterations: usize) -> Self {
        Self {
            iterations,
            max_len: self.max_len,
            seed: self.seed,
            driver_mode: self.driver_mode,
        }
    }

    /// Set the maximum length of a test input
    pub fn with_max_len(self, max_len: usize) -> Self {
        Self {
            iterations: self.iterations,
            max_len,
            seed: self.seed,
            driver_mode: self.driver_mode,
        }
    }

    /// Set the seed for the RNG implementation
    pub fn with_seed(self, seed: u64) -> Self {
        Self {
            iterations: self.iterations,
            max_len: self.max_len,
            seed,
            driver_mode: self.driver_mode,
        }
    }

    /// Set the driver mode for the engine
    pub fn with_driver_mode(self, driver_mode: DriverMode) -> Self {
        Self {
            iterations: self.iterations,
            max_len: self.max_len,
            seed: self.seed,
            driver_mode: Some(driver_mode),
        }
    }
}

impl<T: Test> Engine<T> for RngEngine
where
    T::Value: 'static + Debug + Send,
{
    type Output = ();

    fn set_driver_mode(&mut self, mode: DriverMode) {
        self.driver_mode = Some(mode);
    }

    fn run<I: Instrument + RefUnwindSafe>(self, mut test: T, mut instrument: I) -> Self::Output {
        panic::set_hook();

        let mut state = RngState::new(self.seed, self.max_len, self.driver_mode);

        let mut count = 0;
        while count < self.iterations {
            match test.test(&mut state.next_input(), &mut instrument) {
                Ok(true) => {
                    count += 1;
                    continue;
                }
                Ok(false) => {
                    continue;
                }
                Err(_) => {
                    let failure = test
                        .shrink(
                            replace(&mut state.buffer, vec![]),
                            Some(self.seed),
                            Some(state.driver_mode),
                        )
                        .expect("test should fail");

                    eprintln!("{}", failure);
                    instrument.finish();

                    std::panic::resume_unwind(Box::new(failure));
                }
            }
        }

        instrument.finish();
    }
}

struct RngState {
    rng: StdRng,
    max_len: usize,
    driver_mode: DriverMode,
    buffer: Vec<u8>,
}

impl RngState {
    fn new(seed: u64, max_len: usize, driver_mode: Option<DriverMode>) -> Self {
        Self {
            rng: StdRng::seed_from_u64(seed),
            max_len,
            driver_mode: driver_mode.unwrap_or(DriverMode::Forced),
            buffer: vec![],
        }
    }

    fn next_input(&mut self) -> ByteSliceTestInput {
        let len = self.rng.gen_range(0, self.max_len);
        self.buffer.clear();
        self.buffer.resize(len, 0);
        self.rng.fill_bytes(&mut self.buffer);
        ByteSliceTestInput::new(&self.buffer, Some(self.driver_mode))
    }
}

fn get_var<T: std::str::FromStr>(name: &str) -> Option<T> {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<T>().ok())
}
