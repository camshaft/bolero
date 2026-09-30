#![cfg_attr(fuzzing_random, allow(dead_code))]

use bolero_engine::{rng::Recommended as Rng, Seed};
use bolero_generator::{driver, TypeGenerator};
use rand::SeedableRng;
use std::{io::Read, path::PathBuf};

pub use bolero_engine::input::*;

pub enum Test {
    File(FileTest),
    Rng(RngTest),
}

impl Test {
    pub fn seed(&self) -> Option<Seed> {
        match self {
            Test::File(_) => None,
            Test::Rng(t) => Some(t.seed),
        }
    }
}

pub struct FileTest {
    pub path: PathBuf,
}

impl FileTest {
    pub fn read_into(&self, input: &mut Vec<u8>) {
        std::fs::File::open(&self.path)
            .unwrap()
            .read_to_end(input)
            .unwrap();
    }
}

pub struct RngTest {
    pub seed: Seed,
}

impl RngTest {
    #[inline]
    pub fn rng(&self) -> Rng {
        Rng::from_seed(self.seed.to_le_bytes())
    }

    #[inline]
    pub fn driver(&self, options: &driver::Options) -> driver::Rng<Rng> {
        let rng = Rng::from_seed(self.seed.to_le_bytes());
        driver::Rng::new(rng, options)
    }

    #[inline]
    pub fn input<'a>(
        &self,
        buffer: &'a mut Vec<u8>,
        cache: &'a mut driver::cache::Cache,
        options: &'a driver::Options,
    ) -> cache::Driver<'a, driver::Rng<Rng>> {
        let driver = self.driver(options);
        cache::Driver::new(driver, cache, buffer)
    }

    #[inline]
    pub fn buffered_input<'a>(
        &self,
        buffer: &'a mut Vec<u8>,
        options: &'a driver::Options,
    ) -> RngBufferedInput<'a> {
        let rng = self.rng();
        let driver = BufferedRng { rng, buffer };
        let driver = driver::Rng::new(driver, options);
        RngBufferedInput {
            driver,
            slice: vec![],
        }
    }
}

pub struct BufferedRng<'a> {
    rng: Rng,
    buffer: &'a mut Vec<u8>,
}

impl rand::RngCore for BufferedRng<'_> {
    fn next_u32(&mut self) -> u32 {
        let mut data = [0; 4];
        self.fill_bytes(&mut data);
        u32::from_le_bytes(data)
    }

    fn next_u64(&mut self) -> u64 {
        let mut data = [0; 8];
        self.fill_bytes(&mut data);
        u64::from_le_bytes(data)
    }

    fn fill_bytes(&mut self, bytes: &mut [u8]) {
        self.rng.fill_bytes(bytes);
        self.buffer.extend_from_slice(bytes);
    }
}

pub struct RngBufferedInput<'a> {
    driver: driver::Rng<BufferedRng<'a>>,
    slice: Vec<u8>,
}

impl<'a, Output> Input<Output> for RngBufferedInput<'a> {
    type Driver = driver::Rng<BufferedRng<'a>>;

    fn with_slice<F: FnMut(&[u8]) -> Output>(&mut self, f: &mut F) -> Output {
        self.slice.mutate(&mut self.driver);
        f(&self.slice)
    }

    fn with_driver<F: FnMut(&mut Self::Driver) -> Output>(&mut self, f: &mut F) -> Output {
        f(&mut self.driver)
    }
}

#[allow(dead_code)]
pub struct ReplayRng<'a> {
    buffer: &'a [u8],
}

impl rand::RngCore for ReplayRng<'_> {
    fn next_u32(&mut self) -> u32 {
        let mut data = [0; 4];
        self.fill_bytes(&mut data);
        u32::from_le_bytes(data)
    }

    fn next_u64(&mut self) -> u64 {
        let mut data = [0; 8];
        self.fill_bytes(&mut data);
        u64::from_le_bytes(data)
    }

    fn fill_bytes(&mut self, bytes: &mut [u8]) {
        let len = self.buffer.len().min(bytes.len());
        let (copy_from, remaining) = self.buffer.split_at(len);
        let (copy_to, fill_to) = bytes.split_at_mut(len);
        copy_to.copy_from_slice(copy_from);
        fill_to.fill(0);
        self.buffer = remaining;
    }
}

pub struct RngReplayInput<'a> {
    pub buffer: &'a mut Vec<u8>,
}

impl bolero_engine::shrink::Input for RngReplayInput<'_> {
    type Driver<'d>
        = driver::Rng<ReplayRng<'d>>
    where
        Self: 'd;

    #[inline]
    fn driver(&self, len: usize, options: &driver::Options) -> Self::Driver<'_> {
        let buffer = &self.buffer[..len];
        let rng = ReplayRng { buffer };
        driver::Rng::new(rng, options)
    }
}

impl AsRef<Vec<u8>> for RngReplayInput<'_> {
    #[inline]
    fn as_ref(&self) -> &Vec<u8> {
        self.buffer
    }
}

impl AsMut<Vec<u8>> for RngReplayInput<'_> {
    #[inline]
    fn as_mut(&mut self) -> &mut Vec<u8> {
        self.buffer
    }
}

pub struct ExhastiveInput<'a> {
    pub buffer: &'a mut Vec<u8>,
    pub driver: &'a mut driver::exhaustive::Driver,
}

impl<Output> Input<Output> for ExhastiveInput<'_> {
    type Driver = driver::exhaustive::Driver;

    fn with_slice<F: FnMut(&[u8]) -> Output>(&mut self, f: &mut F) -> Output {
        self.buffer.mutate(&mut self.driver);
        f(self.buffer)
    }

    fn with_driver<F: FnMut(&mut Self::Driver) -> Output>(&mut self, f: &mut F) -> Output {
        f(self.driver)
    }
}

impl AsRef<Vec<u8>> for ExhastiveInput<'_> {
    #[inline]
    fn as_ref(&self) -> &Vec<u8> {
        self.buffer
    }
}

impl AsMut<Vec<u8>> for ExhastiveInput<'_> {
    #[inline]
    fn as_mut(&mut self) -> &mut Vec<u8> {
        self.buffer
    }
}

#[cfg(test)]
mod shrink_regression_328 {
    use super::*;
    use bolero_engine::{ClonedGeneratorTest, Test};
    use bolero_generator::produce;
    use std::time::Duration;

    // Regression for <https://github.com/camshaft/bolero/issues/328> (defect 2):
    // a random-mode failure from a multi-byte generator must shrink to the
    // minimal counterexample.
    //
    // `run_tests` records the rng stream that produced the failure and shrinks
    // it. Shrinking that recording as a plain `Vec<u8>` replays it through a
    // `ByteSliceDriver`, generating a *different* value that often passes, so the
    // shrinker gives up and reports the original, unshrunk failure. Replaying it
    // as an `RngReplayInput` uses the same `driver::Rng` that produced the
    // failure, faithfully reproducing it so it can be minimized.
    //
    // The seed (from the issue) reproduces the divergence deterministically on
    // every platform - the rng and generators are platform-independent.
    #[test]
    fn rng_recording_shrinks_via_replay_not_byte_slice() {
        let seed: Seed = 18941062287044942462312765863378128962;
        let rng_test = RngTest { seed };
        let options = driver::Options::default().with_shrink_time(Duration::from_secs(2));

        // Fails for any input of 8+ bytes, so the minimal counterexample is 8.
        let make_test = || {
            ClonedGeneratorTest::new(
                |value: Vec<u8>| assert!(value.len() < 8, "len = {}", value.len()),
                produce::<Vec<u8>>(),
            )
        };

        // Record the rng stream that produced the failure (mirrors `run_tests`).
        let mut buffer = vec![];
        {
            let test = make_test();
            let mut input = rng_test.buffered_input(&mut buffer, &options);
            let value = test.generate_value(&mut input);
            assert!(value.len() >= 8, "seed no longer produces a failing input");
        }

        // Fix: replaying through `RngReplayInput` reproduces the failure and
        // shrinks it to the minimal 8-byte input.
        let mut replay = buffer.clone();
        let mut test = make_test();
        let shrunk = test
            .shrink(
                RngReplayInput {
                    buffer: &mut replay,
                },
                Some(seed),
                &options,
            )
            .expect("RngReplayInput must reproduce and shrink the failure");
        assert_eq!(
            shrunk.input.len(),
            8,
            "RngReplayInput did not shrink to the minimal length"
        );

        // Bug: shrinking the same recording as a plain `Vec<u8>` does not reach
        // the minimal input (it replays a different value). Asserting the paths
        // diverge documents why `run_tests` must use `RngReplayInput`.
        let mut test = make_test();
        let byte_slice = test.shrink(buffer.clone(), Some(seed), &options);
        assert!(
            byte_slice.map_or(true, |f| f.input.len() != 8),
            "the plain Vec<u8> path unexpectedly shrank to minimal; \
             the regression guard's seed needs updating"
        );
    }
}
