use crate::TypeGenerator;
use rand_core::RngCore;

pub trait Driver: Sized {
    fn gen<T: TypeGenerator>(&mut self) -> Option<T> {
        T::generate(self)
    }

    fn mode(&self) -> DriverMode;

    fn fill_bytes(&mut self, bytes: &mut [u8]) -> Option<()>;
}

#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Eq, Ord)]
pub enum DriverMode {
    Direct,
    Forced,
}

impl<R: RngCore> Driver for R {
    fn mode(&self) -> DriverMode {
        DriverMode::Forced
    }

    fn fill_bytes(&mut self, bytes: &mut [u8]) -> Option<()> {
        RngCore::try_fill_bytes(self, bytes).ok()
    }
}

#[derive(Debug)]
pub struct FuzzDriver<'a> {
    mode: DriverMode,
    input: &'a [u8],
}

impl<'a> FuzzDriver<'a> {
    pub fn new(input: &'a [u8], mode: Option<DriverMode>) -> Self {
        let randomized = mode.is_none();

        let mut driver = Self {
            input,
            mode: mode.unwrap_or(DriverMode::Direct),
        };

        // randomize the driver mode for better coverage
        if randomized {
            driver.mode = if driver.gen().unwrap_or_default() {
                DriverMode::Forced
            } else {
                DriverMode::Direct
            };
        }

        driver
    }
}

impl<'a> Driver for FuzzDriver<'a> {
    fn mode(&self) -> DriverMode {
        self.mode
    }

    fn fill_bytes(&mut self, bytes: &mut [u8]) -> Option<()> {
        if bytes.len() > self.input.len() {
            return None;
        }
        let (current, remaining) = self.input.split_at(bytes.len());
        bytes.copy_from_slice(current);
        self.input = remaining;
        Some(())
    }
}

#[derive(Debug)]
pub struct DirectRng<R: RngCore>(R);

impl<R: RngCore> DirectRng<R> {
    pub fn new(rng: R) -> Self {
        Self(rng)
    }
}

impl<R: RngCore> Driver for DirectRng<R> {
    fn mode(&self) -> DriverMode {
        DriverMode::Direct
    }

    fn fill_bytes(&mut self, bytes: &mut [u8]) -> Option<()> {
        RngCore::try_fill_bytes(&mut self.0, bytes).ok()
    }
}
