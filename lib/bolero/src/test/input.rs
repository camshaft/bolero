#![cfg_attr(fuzzing_random, allow(dead_code))]

use bolero_engine::{rng::Recommended as Rng, Seed};
use bolero_generator::{driver, TypeGenerator};
use core::convert::Infallible;
use rand::{Rng as _, SeedableRng};
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

impl rand::TryRng for BufferedRng<'_> {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut data = [0; 4];
        self.try_fill_bytes(&mut data)?;
        Ok(u32::from_le_bytes(data))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut data = [0; 8];
        self.try_fill_bytes(&mut data)?;
        Ok(u64::from_le_bytes(data))
    }

    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), Self::Error> {
        self.rng.fill_bytes(bytes);
        self.buffer.extend_from_slice(bytes);
        Ok(())
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

impl rand::TryRng for ReplayRng<'_> {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut data = [0; 4];
        self.try_fill_bytes(&mut data)?;
        Ok(u32::from_le_bytes(data))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut data = [0; 8];
        self.try_fill_bytes(&mut data)?;
        Ok(u64::from_le_bytes(data))
    }

    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), Self::Error> {
        let len = self.buffer.len().min(bytes.len());
        let (copy_from, remaining) = self.buffer.split_at(len);
        let (copy_to, fill_to) = bytes.split_at_mut(len);
        copy_to.copy_from_slice(copy_from);
        fill_to.fill(0);
        self.buffer = remaining;
        Ok(())
    }
}

#[allow(dead_code)]
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
