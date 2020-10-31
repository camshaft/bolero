use crate::TypeGenerator;
use rand_core::RngCore;

/// Trait for driving the generation of a value
///
/// In a test engine, this is typically backed by
/// a byte slice, but other drivers can be used instead, e.g.
/// an RNG implementation.
pub trait Driver: Sized {
    /// Generate a value with type `T`
    fn gen<T: TypeGenerator>(&mut self) -> Option<T> {
        T::generate(self)
    }

    /// Return the mode set for the driver
    fn mode(&self) -> DriverMode;

    /// Fill the target bytes with the driver state
    fn fill_bytes(&mut self, bytes: &mut [u8]) -> Option<()>;
}

/// Byte exhaustion strategy for the driver
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Eq, Ord)]
pub enum DriverMode {
    /// When the driver bytes are exhausted, the driver will fail fill input bytes.
    /// This is useful for fuzz engines that want accurate mapping of inputs to coverage.
    Direct,

    /// When the driver bytes are exhausted, the driver will continue to fill input bytes with 0.
    /// This is useful for engines that want to maximize the amount of time spent executing tests.
    Forced,
}

#[derive(Debug)]
pub struct ByteSliceDriver<'a> {
    mode: DriverMode,
    input: &'a [u8],
}

impl<'a> ByteSliceDriver<'a> {
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

    pub fn new_direct(input: &'a [u8]) -> Self {
        Self::new(input, Some(DriverMode::Direct))
    }

    pub fn new_forced(input: &'a [u8]) -> Self {
        Self::new(input, Some(DriverMode::Forced))
    }
}

impl<'a> Driver for ByteSliceDriver<'a> {
    fn mode(&self) -> DriverMode {
        self.mode
    }

    fn fill_bytes(&mut self, bytes: &mut [u8]) -> Option<()> {
        match self.mode {
            DriverMode::Forced => {
                let offset = self.input.len().min(bytes.len());
                let (current, remaining) = self.input.split_at(offset);
                let (bytes_to_fill, bytes_to_zero) = bytes.split_at_mut(offset);
                bytes_to_fill.copy_from_slice(current);
                for byte in bytes_to_zero.iter_mut() {
                    *byte = 0;
                }
                self.input = remaining;
                Some(())
            }
            DriverMode::Direct => {
                if bytes.len() > self.input.len() {
                    return None;
                }
                let (current, remaining) = self.input.split_at(bytes.len());
                bytes.copy_from_slice(current);
                self.input = remaining;
                Some(())
            }
        }
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

#[derive(Debug)]
pub struct ForcedRng<R: RngCore>(R);

impl<R: RngCore> ForcedRng<R> {
    pub fn new(rng: R) -> Self {
        Self(rng)
    }
}

impl<R: RngCore> Driver for ForcedRng<R> {
    fn mode(&self) -> DriverMode {
        DriverMode::Forced
    }

    fn fill_bytes(&mut self, bytes: &mut [u8]) -> Option<()> {
        if RngCore::try_fill_bytes(&mut self.0, bytes).is_err() {
            for byte in bytes.iter_mut() {
                *byte = 0;
            }
        }
        Some(())
    }
}
