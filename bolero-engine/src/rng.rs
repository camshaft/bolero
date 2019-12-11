use crate::{panic, Engine, SliceTestInput, TargetLocation, Test};
use bolero_generator::driver::DriverMode;
use core::{fmt::Debug, mem::replace};
use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};

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
    pub fn new(_location: TargetLocation) -> Self {
        Self::default()
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

    fn run(self, mut test: T) -> Self::Output {
        panic::set_hook();

        let mut state = RngState::new(self.seed, self.max_len, self.driver_mode);

        let mut count = 0;
        while count < self.iterations {
            match test.test(&mut state.next_input()) {
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

                    std::panic::resume_unwind(Box::new(failure));
                }
            }
        }
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

    fn next_input(&mut self) -> SliceTestInput {
        let len = self.rng.gen_range(0, self.max_len);
        self.buffer.clear();
        self.buffer.resize(len, 0);
        self.rng.fill_bytes(&mut self.buffer);
        SliceTestInput::new(&self.buffer, Some(self.driver_mode))
    }
}

fn get_var<T: std::str::FromStr>(name: &str) -> Option<T> {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<T>().ok())
}
