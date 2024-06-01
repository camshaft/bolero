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

impl<'a> rand::RngCore for BufferedRng<'a> {
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

    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), rand::Error> {
        self.rng.try_fill_bytes(bytes)?;
        self.buffer.extend_from_slice(bytes);
        Ok(())
    }

    fn fill_bytes(&mut self, bytes: &mut [u8]) {
        self.try_fill_bytes(bytes).unwrap()
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

pub struct ReplayRng<'a> {
    buffer: &'a [u8],
}

impl<'a> rand::RngCore for ReplayRng<'a> {
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

    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), rand::Error> {
        let len = self.buffer.len().min(bytes.len());
        let (copy_from, remaining) = self.buffer.split_at(len);
        let (copy_to, fill_to) = bytes.split_at_mut(len);
        copy_to.copy_from_slice(copy_from);
        fill_to.fill(0);
        self.buffer = remaining;
        Ok(())
    }

    fn fill_bytes(&mut self, bytes: &mut [u8]) {
        self.try_fill_bytes(bytes).unwrap()
    }
}

pub struct RngReplayInput<'a> {
    pub buffer: &'a mut Vec<u8>,
}

impl<'a> bolero_engine::shrink::Input for RngReplayInput<'a> {
    type Driver<'d> = driver::Rng<ReplayRng<'d>>
        where
            Self: 'd;

    #[inline]
    fn driver(&self, len: usize, options: &driver::Options) -> Self::Driver<'_> {
        let buffer = &self.buffer[..len];
        let rng = ReplayRng { buffer };
        driver::Rng::new(rng, options)
    }
}

impl<'a> AsRef<Vec<u8>> for RngReplayInput<'a> {
    #[inline]
    fn as_ref(&self) -> &Vec<u8> {
        self.buffer
    }
}

impl<'a> AsMut<Vec<u8>> for RngReplayInput<'a> {
    #[inline]
    fn as_mut(&mut self) -> &mut Vec<u8> {
        self.buffer
    }
}
