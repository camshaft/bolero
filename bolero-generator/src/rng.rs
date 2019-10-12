use crate::TypeGenerator;
use core::{
    iter::{once, Chain, Cycle, Once},
    slice::Iter as SliceIter,
};
use rand_core::{Error as RngError, RngCore};

pub trait Rng {
    fn gen<T: TypeGenerator>(&mut self) -> T;
    fn next_u32(&mut self) -> u32;
    fn next_u64(&mut self) -> u64;
    fn fill_bytes(&mut self, bytes: &mut [u8]);
}

impl<R: RngCore> Rng for R {
    fn gen<T: TypeGenerator>(&mut self) -> T {
        T::generate(self)
    }

    fn next_u32(&mut self) -> u32 {
        RngCore::next_u32(self)
    }

    fn next_u64(&mut self) -> u64 {
        RngCore::next_u64(self)
    }

    fn fill_bytes(&mut self, bytes: &mut [u8]) {
        RngCore::fill_bytes(self, bytes)
    }
}

pub struct FuzzRng<'a> {
    input: Chain<SliceIter<'a, u8>, Cycle<Once<&'a u8>>>,
}

impl<'a> FuzzRng<'a> {
    pub fn new(input: &'a [u8]) -> Self {
        Self {
            input: input.iter().chain(once(&0).cycle()),
        }
    }
}

impl<'a> RngCore for FuzzRng<'a> {
    fn next_u32(&mut self) -> u32 {
        self.gen()
    }

    fn next_u64(&mut self) -> u64 {
        self.gen()
    }

    fn fill_bytes(&mut self, bytes: &mut [u8]) {
        for (from, to) in (&mut self.input).zip(bytes.iter_mut()) {
            *to = *from;
        }
    }

    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), RngError> {
        RngCore::fill_bytes(self, bytes);
        Ok(())
    }
}
