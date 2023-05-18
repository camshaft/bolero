use crate::{Driver, Options};
use bolero_generator::driver::ByteSliceDriver;
use core::fmt;
use pretty_hex::pretty_hex_write;
use std::panic::RefUnwindSafe;

pub trait TestInput<Output> {
    type Driver: Driver + RefUnwindSafe;

    /// Provide a slice of the test input
    fn with_slice<F: FnMut(&[u8]) -> Output>(&mut self, f: &mut F) -> Output;

    /// Provide a test driver for the test input
    ///
    /// Note: Drivers are used with `bolero_generator::ValueGenerator` implementations.
    fn with_driver<F: FnMut(&mut Self::Driver) -> Output>(&mut self, f: &mut F) -> Output;
}

/*
impl<'a, Output> TestInput<Output> for &'a [u8] {
    type Driver = ByteSliceDriver<'a>;

    fn with_slice<F: FnMut(&[u8]) -> Output>(&mut self, f: &mut F) -> Output {
        f(self)
    }

    fn with_driver<F: FnMut(&mut Self::Driver) -> Output>(&mut self, f: &mut F) -> Output {
        f(&mut ByteSliceDriver::new(self, None))
    }
}
*/

#[derive(Clone, Copy, Debug)]
pub struct ByteSliceTestInput<'a> {
    slice: &'a [u8],
    options: &'a Options,
}

impl<'a> ByteSliceTestInput<'a> {
    // add code here
    pub fn new(slice: &'a [u8], options: &'a Options) -> Self {
        Self { slice, options }
    }
}

impl<'a, Output> TestInput<Output> for ByteSliceTestInput<'a> {
    type Driver = ByteSliceDriver<'a>;

    fn with_slice<F: FnMut(&[u8]) -> Output>(&mut self, f: &mut F) -> Output {
        f(self.slice)
    }

    fn with_driver<F: FnMut(&mut Self::Driver) -> Output>(&mut self, f: &mut F) -> Output {
        f(&mut ByteSliceDriver::new(self.slice, self.options))
    }
}

#[cfg(feature = "rng")]
#[derive(Debug)]
pub struct RngInput<'a, R: rand::RngCore> {
    slice: &'a mut Vec<u8>,
    rng: bolero_generator::driver::Rng<R>,
}

#[cfg(feature = "rng")]
impl<'a, R: rand::RngCore + core::panic::RefUnwindSafe> RngInput<'a, R> {
    pub fn new(rng: R, slice: &'a mut Vec<u8>, options: &'a Options) -> Self {
        Self {
            slice,
            rng: bolero_generator::driver::Rng::new(rng, options),
        }
    }
}

#[cfg(feature = "rng")]
impl<'a, Output, R: rand::RngCore + core::panic::RefUnwindSafe> TestInput<Output>
    for RngInput<'a, R>
{
    type Driver = bolero_generator::driver::Rng<R>;

    fn with_slice<F: FnMut(&[u8]) -> Output>(&mut self, f: &mut F) -> Output {
        bolero_generator::TypeGenerator::mutate(self.slice, &mut self.rng);
        f(self.slice)
    }

    fn with_driver<F: FnMut(&mut Self::Driver) -> Output>(&mut self, f: &mut F) -> Output {
        f(&mut self.rng)
    }
}

#[derive(Clone, Copy)]
pub struct SliceDebug<T>(pub(crate) T);

impl<T> core::ops::Deref for SliceDebug<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: AsRef<[u8]>> fmt::Debug for SliceDebug<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        pretty_hex_write(f, &self.0.as_ref())
    }
}
