use crate::{
    test_input::SliceDebug, DriverMode, Error, Instrument, IntoTestResult, Measurement,
    TestFailure, TestInput, ValueGenerator,
};
use std::panic::RefUnwindSafe;

pub trait Test: Sized {
    type Value;

    fn test<T: TestInput<Result<bool, Error>>, I: Instrument + RefUnwindSafe>(
        &mut self,
        input: &mut T,
        instrument: &mut I,
    ) -> Result<bool, Error>;

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
    type Value = SliceDebug<Vec<u8>>;

    fn test<T: TestInput<Result<bool, Error>>, I: Instrument + RefUnwindSafe>(
        &mut self,
        input: &mut T,
        instrument: &mut I,
    ) -> Result<bool, Error> {
        input.with_slice(&mut |slice| {
            crate::panic::catch(|| {
                let measurement = instrument.start();
                let res = (self)(slice);
                let record = measurement.stop();
                match res.into_test_result() {
                    Ok(()) => {
                        instrument.record(record, &SliceDebug(slice));
                        Ok(true)
                    }
                    Err(err) => Err(err),
                }
            })?
        })
    }

    fn generate_value<T: TestInput<Self::Value>>(&self, input: &mut T) -> Self::Value {
        input.with_slice(&mut |slice| SliceDebug(slice.to_vec()))
    }
}

pub struct BorrowedSliceTest<F> {
    fun: F,
}

impl<F> BorrowedSliceTest<F> {
    pub fn new(fun: F) -> Self {
        Self { fun }
    }
}

impl<F: RefUnwindSafe + FnMut(&[u8]) -> Ret, Ret> Test for BorrowedSliceTest<F>
where
    Ret: IntoTestResult,
{
    type Value = SliceDebug<Vec<u8>>;

    fn test<T: TestInput<Result<bool, Error>>, I: Instrument + RefUnwindSafe>(
        &mut self,
        input: &mut T,
        instrument: &mut I,
    ) -> Result<bool, Error> {
        input.with_slice(&mut |slice| {
            crate::panic::catch(|| {
                let measurement = instrument.start();
                let res = (self.fun)(slice);
                let record = measurement.stop();
                match res.into_test_result() {
                    Ok(()) => {
                        instrument.record(record, &SliceDebug(slice));
                        Ok(true)
                    }
                    Err(err) => Err(err),
                }
            })?
        })
    }

    fn generate_value<T: TestInput<Self::Value>>(&self, input: &mut T) -> Self::Value {
        input.with_slice(&mut |slice| SliceDebug(slice.to_vec()))
    }
}

pub struct ClonedSliceTest<F> {
    fun: F,
}

impl<F> ClonedSliceTest<F> {
    pub fn new(fun: F) -> Self {
        Self { fun }
    }
}

impl<F: RefUnwindSafe + FnMut(Vec<u8>) -> Ret, Ret> Test for ClonedSliceTest<F>
where
    Ret: IntoTestResult,
{
    type Value = SliceDebug<Vec<u8>>;

    fn test<T: TestInput<Result<bool, Error>>, I: Instrument + RefUnwindSafe>(
        &mut self,
        input: &mut T,
        instrument: &mut I,
    ) -> Result<bool, Error> {
        input.with_slice(&mut |slice| {
            crate::panic::catch(|| {
                let input = slice.to_vec();
                let measurement = instrument.start();
                let res = (self.fun)(input);
                let record = measurement.stop();
                match res.into_test_result() {
                    Ok(()) => {
                        instrument.record(record, &SliceDebug(slice));
                        Ok(true)
                    }
                    Err(err) => Err(err),
                }
            })?
        })
    }

    fn generate_value<T: TestInput<Self::Value>>(&self, input: &mut T) -> Self::Value {
        input.with_slice(&mut |slice| SliceDebug(slice.to_vec()))
    }
}

pub struct BorrowedGeneratorTest<F, G, V> {
    fun: F,
    gen: G,
    value: Option<V>,
}

impl<F, G, V> BorrowedGeneratorTest<F, G, V> {
    pub fn new(fun: F, gen: G) -> Self {
        Self {
            fun,
            gen,
            value: None,
        }
    }
}

impl<F: RefUnwindSafe + FnMut(&G::Output) -> Ret, G: RefUnwindSafe + ValueGenerator, Ret> Test
    for BorrowedGeneratorTest<F, G, G::Output>
where
    Ret: IntoTestResult,
    G::Output: RefUnwindSafe + core::fmt::Debug,
{
    type Value = G::Output;

    fn test<T: TestInput<Result<bool, Error>>, I: Instrument + RefUnwindSafe>(
        &mut self,
        input: &mut T,
        instrument: &mut I,
    ) -> Result<bool, Error> {
        input.with_driver(&mut |driver| {
            let fun = &mut self.fun;

            let value = if let Some(value) = self.value.as_mut() {
                if self.gen.mutate(driver, value).is_some() {
                    value
                } else {
                    return Ok(false);
                }
            } else if let Some(value) = self.gen.generate(driver) {
                self.value = Some(value);
                self.value.as_ref().unwrap()
            } else {
                return Ok(false);
            };

            crate::panic::catch(|| {
                let measurement = instrument.start();
                let res = (fun)(value);
                let record = measurement.stop();
                match res.into_test_result() {
                    Ok(()) => {
                        instrument.record(record, value);
                        Ok(true)
                    }
                    Err(err) => Err(err),
                }
            })?
        })
    }

    fn generate_value<T: TestInput<Self::Value>>(&self, input: &mut T) -> Self::Value {
        input.with_driver(&mut |driver| self.gen.generate(driver).unwrap())
    }
}

pub struct ClonedGeneratorTest<F, G, V> {
    fun: F,
    gen: G,
    value: Option<V>,
}

impl<F, G, V> ClonedGeneratorTest<F, G, V> {
    pub fn new(fun: F, gen: G) -> Self {
        Self {
            fun,
            gen,
            value: None,
        }
    }
}

impl<F: RefUnwindSafe + FnMut(G::Output) -> Ret, G: RefUnwindSafe + ValueGenerator, Ret> Test
    for ClonedGeneratorTest<F, G, G::Output>
where
    Ret: IntoTestResult,
    G::Output: RefUnwindSafe + core::fmt::Debug + Clone,
{
    type Value = G::Output;

    fn test<T: TestInput<Result<bool, Error>>, I: Instrument + RefUnwindSafe>(
        &mut self,
        input: &mut T,
        instrument: &mut I,
    ) -> Result<bool, Error> {
        input.with_driver(&mut |driver| {
            let fun = &mut self.fun;

            let value = if let Some(value) = self.value.as_mut() {
                if self.gen.mutate(driver, value).is_some() {
                    value
                } else {
                    return Ok(false);
                }
            } else if let Some(value) = self.gen.generate(driver) {
                self.value = Some(value);
                self.value.as_ref().unwrap()
            } else {
                return Ok(false);
            };

            let input = value.clone();

            crate::panic::catch(|| {
                let measurement = instrument.start();
                let res = (fun)(input);
                let record = measurement.stop();
                match res.into_test_result() {
                    Ok(()) => {
                        instrument.record(record, &value);
                        Ok(true)
                    }
                    Err(err) => Err(err),
                }
            })?
        })
    }

    fn generate_value<T: TestInput<Self::Value>>(&self, input: &mut T) -> Self::Value {
        input.with_driver(&mut |driver| self.gen.generate(driver).unwrap())
    }
}
