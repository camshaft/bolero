use crate::{panic, ByteSliceTestInput, Engine, Options, TargetLocation, Test};
use core::fmt::Debug;
use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};

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
    options: Options,
}

impl Default for RngEngine {
    fn default() -> Self {
        if cfg!(miri) {
            // RNG tests are really slow with miri so we limit the number of iterations
            let iterations = get_var("BOLERO_RANDOM_ITERATIONS").unwrap_or(25);
            let max_len = get_var("BOLERO_RANDOM_MAX_LEN").unwrap_or(1024);
            let seed =
                get_var("BOLERO_RANDOM_SEED").unwrap_or_else(|| rand::thread_rng().next_u64());

            return Self {
                iterations,
                max_len,
                seed,
                options: Default::default(),
            };
        }

        let iterations = get_var("BOLERO_RANDOM_ITERATIONS").unwrap_or(1000);
        let max_len = get_var("BOLERO_RANDOM_MAX_LEN").unwrap_or(4096);
        let seed = get_var("BOLERO_RANDOM_SEED").unwrap_or_else(|| rand::thread_rng().next_u64());

        Self {
            iterations,
            max_len,
            seed,
            options: Default::default(),
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

    fn set_options(&mut self, options: &Options) {
        self.options = options.clone();
    }

    fn run(self, mut test: T) -> Self::Output {
        panic::set_hook();

        let mut state = RngState::new(self.seed, self.max_len, &self.options);

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
                            &self.options,
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

struct RngState<'a> {
    rng: StdRng,
    max_len: usize,
    buffer: Vec<u8>,
    options: &'a Options,
}

impl<'a> RngState<'a> {
    fn new(seed: u64, max_len: usize, options: &'a Options) -> Self {
        Self {
            rng: StdRng::seed_from_u64(seed),
            max_len,
            buffer: vec![],
            options,
        }
    }

    fn next_input(&mut self) -> ByteSliceTestInput {
        let len = self.rng.gen_range(0..self.max_len);
        self.buffer.clear();
        self.buffer.resize(len, 0);
        self.rng.fill_bytes(&mut self.buffer);
        ByteSliceTestInput::new(&self.buffer, self.options)
    }
}

fn get_var<T: std::str::FromStr>(name: &str) -> Option<T> {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<T>().ok())
}
