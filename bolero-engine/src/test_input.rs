use crate::{Driver, DriverMode};
use bolero_generator::driver::FuzzDriver;
use core::fmt;
use pretty_hex::pretty_hex_write;
use std::panic::RefUnwindSafe;

pub trait TestInput<Output> {
    type Driver: Driver + RefUnwindSafe;

    fn with_slice<F: FnMut(&[u8]) -> Output>(&mut self, f: &mut F) -> Output;
    fn with_driver<F: FnMut(&mut Self::Driver) -> Output>(&mut self, f: &mut F) -> Output;
}

impl<'a, Output> TestInput<Output> for &'a [u8] {
    type Driver = FuzzDriver<'a>;

    fn with_slice<F: FnMut(&[u8]) -> Output>(&mut self, f: &mut F) -> Output {
        f(self)
    }

    fn with_driver<F: FnMut(&mut Self::Driver) -> Output>(&mut self, f: &mut F) -> Output {
        f(&mut FuzzDriver::new(self, None))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct SliceTestInput<'a> {
    slice: &'a [u8],
    mode: Option<DriverMode>,
}

impl<'a> SliceTestInput<'a> {
    // add code here
    pub fn new(slice: &'a [u8], mode: Option<DriverMode>) -> Self {
        Self { slice, mode }
    }
}

impl<'a, Output> TestInput<Output> for SliceTestInput<'a> {
    type Driver = FuzzDriver<'a>;

    fn with_slice<F: FnMut(&[u8]) -> Output>(&mut self, f: &mut F) -> Output {
        f(&self.slice)
    }

    fn with_driver<F: FnMut(&mut Self::Driver) -> Output>(&mut self, f: &mut F) -> Output {
        f(&mut FuzzDriver::new(&self.slice, self.mode))
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
