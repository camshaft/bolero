use super::*;

#[derive(Debug)]
pub struct DirectRng<R: RngCore> {
    rng: R,
    depth: usize,
    max_depth: usize,
}

impl<R: RngCore> DirectRng<R> {
    pub fn new(rng: R) -> Self {
        Self {
            rng,
            depth: 0,
            max_depth: super::DEFAULT_MAX_DEPTH,
        }
    }

    #[inline]
    fn fill_bytes(&mut self, bytes: &mut [u8]) -> Option<()> {
        RngCore::try_fill_bytes(&mut self.rng, bytes).ok()
    }
}

impl<R: RngCore> FillBytes for DirectRng<R> {
    #[inline]
    fn mode(&self) -> DriverMode {
        DriverMode::Direct
    }

    #[inline]
    fn peek_bytes(&mut self, _offset: usize, bytes: &mut [u8]) -> Option<()> {
        RngCore::try_fill_bytes(&mut self.rng, bytes).ok()
    }

    #[inline]
    fn consume_bytes(&mut self, _consumed: usize) {}
}

impl<R: RngCore> Driver for DirectRng<R> {
    gen_from_bytes!();

    gen_from_bytes_impl!();

    #[inline]
    fn depth(&mut self) -> &mut usize {
        &mut self.depth
    }

    #[inline]
    fn max_depth(&self) -> usize {
        self.max_depth
    }
}

#[derive(Debug)]
pub struct ForcedRng<R: RngCore> {
    rng: R,
    depth: usize,
    max_depth: usize,
}

impl<R: RngCore> ForcedRng<R> {
    #[inline]
    pub fn new(rng: R) -> Self {
        Self {
            rng,
            depth: 0,
            max_depth: super::DEFAULT_MAX_DEPTH,
        }
    }
}

impl<R: RngCore> FillBytes for ForcedRng<R> {
    #[inline]
    fn mode(&self) -> DriverMode {
        DriverMode::Forced
    }

    #[inline]
    fn peek_bytes(&mut self, _offset: usize, bytes: &mut [u8]) -> Option<()> {
        if RngCore::try_fill_bytes(&mut self.rng, bytes).is_err() {
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

    gen_from_bytes_impl!();

    #[inline]
    fn depth(&mut self) -> &mut usize {
        &mut self.depth
    }

    #[inline]
    fn max_depth(&self) -> usize {
        self.max_depth
    }
}
