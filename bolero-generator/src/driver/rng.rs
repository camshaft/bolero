use super::*;

#[derive(Debug)]
pub struct DirectRng<R: RngCore>(R);

impl<R: RngCore> DirectRng<R> {
    pub fn new(rng: R) -> Self {
        Self(rng)
    }

    #[inline]
    fn fill_bytes(&mut self, bytes: &mut [u8]) -> Option<()> {
        RngCore::try_fill_bytes(&mut self.0, bytes).ok()
    }
}

impl<R: RngCore> FillBytes for DirectRng<R> {
    #[inline]
    fn mode(&self) -> DriverMode {
        DriverMode::Direct
    }

    #[inline]
    fn peek_bytes(&mut self, _offset: usize, bytes: &mut [u8]) -> Option<()> {
        RngCore::try_fill_bytes(&mut self.0, bytes).ok()
    }

    #[inline]
    fn consume_bytes(&mut self, _consumed: usize) {}
}

impl<R: RngCore> Driver for DirectRng<R> {
    gen_from_bytes!();
}

#[derive(Debug)]
pub struct ForcedRng<R: RngCore>(R);

impl<R: RngCore> ForcedRng<R> {
    #[inline]
    pub fn new(rng: R) -> Self {
        Self(rng)
    }
}

impl<R: RngCore> FillBytes for ForcedRng<R> {
    #[inline]
    fn mode(&self) -> DriverMode {
        DriverMode::Forced
    }

    #[inline]
    fn peek_bytes(&mut self, _offset: usize, bytes: &mut [u8]) -> Option<()> {
        if RngCore::try_fill_bytes(&mut self.0, bytes).is_err() {
            // if the rng fails to fill the remaining bytes, then we just start returning 0s
            for byte in bytes.iter_mut() {
                *byte = 0;
            }
        }
        Some(())
    }

    #[inline]
    fn consume_bytes(&mut self, _consumed: usize) {}
}

impl<R: RngCore> Driver for ForcedRng<R> {
    gen_from_bytes!();
}
