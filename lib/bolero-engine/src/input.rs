use crate::{driver, Driver};
use bolero_generator::driver::ByteSliceDriver;
use core::fmt;
use pretty_hex::pretty_hex_write;
use std::panic::RefUnwindSafe;

pub trait Input<Output> {
    type Driver: Driver + RefUnwindSafe;

    /// Provide a slice of the test input
    fn with_slice<F: FnMut(&[u8]) -> Output>(&mut self, f: &mut F) -> Output;

    /// Provide a test driver for the test input
    ///
    /// Note: Drivers are used with `bolero_generator::ValueGenerator` implementations.
    fn with_driver<F: FnMut(&mut Self::Driver) -> Output>(&mut self, f: &mut F) -> Output;
}

impl<'a, Output> Input<Output> for &'a [u8] {
    type Driver = ByteSliceDriver<'a>;

    fn with_slice<F: FnMut(&[u8]) -> Output>(&mut self, f: &mut F) -> Output {
        f(self)
    }

    fn with_driver<F: FnMut(&mut Self::Driver) -> Output>(&mut self, f: &mut F) -> Output {
        let options = driver::Options::default();
        f(&mut ByteSliceDriver::new(self, &options))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Bytes<'a> {
    slice: &'a [u8],
    options: &'a driver::Options,
}

impl<'a> Bytes<'a> {
    pub fn new(slice: &'a [u8], options: &'a driver::Options) -> Self {
        Self { slice, options }
    }
}

impl<'a, Output> Input<Output> for Bytes<'a> {
    type Driver = ByteSliceDriver<'a>;

    fn with_slice<F: FnMut(&[u8]) -> Output>(&mut self, f: &mut F) -> Output {
        f(self.slice)
    }

    fn with_driver<F: FnMut(&mut Self::Driver) -> Output>(&mut self, f: &mut F) -> Output {
        f(&mut ByteSliceDriver::new(self.slice, self.options))
    }
}

#[cfg(feature = "cache")]
pub mod cache {
    use super::*;
    use driver::cache::{self, Cache};

    pub struct Bytes<'a> {
        driver: cache::Driver<'a, ByteSliceDriver<'a>>,
    }

    impl<'a> Bytes<'a> {
        #[inline]
        pub fn new(slice: &'a [u8], options: &'a driver::Options, cache: &'a mut Cache) -> Self {
            let driver = ByteSliceDriver::new(slice, options);
            let driver = cache::Driver::new(driver, cache);
            Self { driver }
        }
    }

    impl<'a, Output> Input<Output> for Bytes<'a> {
        type Driver = cache::Driver<'a, ByteSliceDriver<'a>>;

        #[inline]
        fn with_slice<F: FnMut(&[u8]) -> Output>(&mut self, f: &mut F) -> Output {
            f(self.driver.as_ref().as_slice())
        }

        #[inline]
        fn with_driver<F: FnMut(&mut Self::Driver) -> Output>(&mut self, f: &mut F) -> Output {
            f(&mut self.driver)
        }
    }

    pub struct Driver<'a, I: crate::Driver> {
        slice: &'a mut Vec<u8>,
        driver: cache::Driver<'a, I>,
    }

    impl<'a, I: crate::Driver> Driver<'a, I> {
        #[inline]
        pub fn new(inner: I, cache: &'a mut driver::cache::Cache, slice: &'a mut Vec<u8>) -> Self {
            Self {
                slice,
                driver: cache::Driver::new(inner, cache),
            }
        }
    }

    impl<'a, Output, I: crate::Driver + core::panic::RefUnwindSafe> Input<Output> for Driver<'a, I> {
        type Driver = cache::Driver<'a, I>;

        #[inline]
        fn with_slice<F: FnMut(&[u8]) -> Output>(&mut self, f: &mut F) -> Output {
            bolero_generator::TypeGenerator::mutate(self.slice, &mut self.driver);
            f(self.slice)
        }

        #[inline]
        fn with_driver<F: FnMut(&mut Self::Driver) -> Output>(&mut self, f: &mut F) -> Output {
            f(&mut self.driver)
        }
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
