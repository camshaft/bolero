use crate::{DriverMode, Error, IntoTestResult, TestFailure, TestInput, ValueGenerator};
use std::panic::RefUnwindSafe;

pub trait Test: Sized {
    type Value;

    fn test<T: TestInput<Result<bool, Error>>>(&mut self, input: &mut T) -> Result<bool, Error>;
    fn generate_value<T: TestInput<Self::Value>>(&self, input: &mut T) -> Self::Value;
    fn shrink(
        &mut self,
        input: Vec<u8>,
        seed: Option<u64>,
        driver_mode: Option<DriverMode>,
    ) -> Option<TestFailure<Self::Value>> {
        crate::shrink::shrink(self, input, seed, driver_mode)
    }
}

impl<F: RefUnwindSafe + FnMut(&[u8]) -> Ret, Ret> Test for F
where
    Ret: IntoTestResult,
{
    type Value = Vec<u8>;

    fn test<T: TestInput<Result<bool, Error>>>(&mut self, input: &mut T) -> Result<bool, Error> {
        input.with_slice(&mut |slice| {
            crate::panic::catch(&mut || (self)(slice))?.into_test_result()?;
            Ok(true)
        })
    }

    fn generate_value<T: TestInput<Self::Value>>(&self, input: &mut T) -> Self::Value {
        input.with_slice(&mut |slice| slice.to_owned())
    }
}

pub struct GeneratorTest<F, G> {
    fun: F,
    gen: G,
}

impl<F, G> GeneratorTest<F, G> {
    pub fn new(fun: F, gen: G) -> Self {
        Self { fun, gen }
    }
}

impl<F: RefUnwindSafe + FnMut(G::Output) -> Ret, G: RefUnwindSafe + ValueGenerator, Ret> Test
    for GeneratorTest<F, G>
where
    Ret: IntoTestResult,
    G::Output: RefUnwindSafe,
{
    type Value = G::Output;

    fn test<T: TestInput<Result<bool, Error>>>(&mut self, input: &mut T) -> Result<bool, Error> {
        input.with_driver(&mut |driver| {
            crate::panic::catch(&mut || {
                if let Some(value) = self.gen.generate(driver) {
                    (self.fun)(value).into_test_result().map(|_| true)
                } else {
                    Ok(false)
                }
            })?
        })
    }

    fn generate_value<T: TestInput<Self::Value>>(&self, input: &mut T) -> Self::Value {
        input.with_driver(&mut |driver| self.gen.generate(driver).unwrap())
    }
}
