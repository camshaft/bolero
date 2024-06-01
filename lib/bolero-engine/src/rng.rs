use crate::Seed;
use core::{fmt::Debug, time::Duration};

pub use rand_xoshiro::Xoroshiro128PlusPlus as Recommended;

#[derive(Clone, Copy, Debug)]
pub struct Options {
    pub test_time: Option<Duration>,
    pub iterations: Option<usize>,
    pub max_len: Option<usize>,
    pub seed: Option<Seed>,
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
}

fn get_var<T: std::str::FromStr>(name: &str) -> Option<T> {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<T>().ok())
}
