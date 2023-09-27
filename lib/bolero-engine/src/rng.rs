use crate::{driver, panic, ByteSliceTestInput, Engine, TargetLocation, Test};
use core::fmt::Debug;
use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};

#[derive(Clone, Copy, Debug)]
pub struct Options {
    pub iterations: Option<usize>,
    pub max_len: Option<usize>,
    pub seed: Option<u64>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            iterations: get_var("BOLERO_RANDOM_ITERATIONS"),
            max_len: get_var("BOLERO_RANDOM_MAX_LEN"),
            seed: get_var("BOLERO_RANDOM_SEED"),
        }
    }
}

impl Options {
    pub fn iterations_or_default(&self) -> usize {
        // RNG tests are really slow with miri so we limit the number of iterations
        self.iterations
            .unwrap_or(if cfg!(miri) { 25 } else { 1000 })
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

        let mut valid = 0;
        let mut invalid = 0;
        while valid < self.iterations {
            match test.test(&mut state.next_input()) {
                Ok(true) => {
                    valid += 1;
                    continue;
                }
                Ok(false) => {
                    invalid += 1;
                    if invalid > self.iterations * 2 {
                        panic!(
                            concat!(
                                "Test input could not be satisfied after {} iterations:\n",
                                "         valid: {}\n",
                                "       invalid: {}\n",
                                "  target count: {}\n",
                                "\n",
                                "Try reconfiguring the input generator to produce more valid inputs",
                            ),
                            valid + invalid,
                            valid,
                            invalid,
                            self.iterations
                        );
                    }
                    continue;
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
    }
}

struct RngState {
    rng: StdRng,
    max_len: usize,
    options: driver::Options,
    buffer: Vec<u8>,
}

impl RngState {
    fn new(seed: u64, max_len: usize, options: driver::Options) -> Self {
        Self {
            rng: StdRng::seed_from_u64(seed),
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
