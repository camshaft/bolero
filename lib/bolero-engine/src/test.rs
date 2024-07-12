use crate::{
    driver, input::SliceDebug, panic, panic::PanicError, Failure, Input, IntoResult, Seed,
    ValueGenerator,
};
use std::panic::RefUnwindSafe;

/// Trait for defining a test case
pub trait Test: Sized {
    /// The input value for the test case
    type Value: core::fmt::Debug;

    /// Execute one test with the given input
    fn test<T: Input<Result<bool, PanicError>>>(
        &mut self,
        input: &mut T,
    ) -> Result<bool, PanicError>;

    /// Generate a value for the given input.
    ///
    /// Note: this is used for printing the value related to a test failure
    fn generate_value<T: Input<Self::Value>>(&self, input: &mut T) -> Self::Value;

    /// Shrink the input to a simpler form
    fn shrink<I: crate::shrink::Input>(
        &mut self,
        input: I,
        seed: Option<Seed>,
        options: &driver::Options,
    ) -> Option<Failure<Self::Value>> {
        crate::shrink::shrink(self, input, seed, options)
    }

    /// Called when the test fails
    fn on_failure(&mut self, failure: Failure<Self::Value>) {
        failure.exit();
    }
}

impl<F: RefUnwindSafe + FnMut(&[u8]) -> Ret, Ret> Test for F
where
    Ret: IntoResult,
{
    type Value = SliceDebug<Vec<u8>>;

    #[inline]
    fn test<T: Input<Result<bool, PanicError>>>(
        &mut self,
        input: &mut T,
    ) -> Result<bool, PanicError> {
        input.with_slice(&mut |slice| {
            panic::catch(|| {
                let res = (self)(slice);
                match res.into_result() {
                    Ok(()) => Ok(true),
                    Err(err) => Err(err),
                }
            })
        })
    }

    #[inline]
    fn generate_value<T: Input<Self::Value>>(&self, input: &mut T) -> Self::Value {
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
    Ret: IntoResult,
{
    type Value = SliceDebug<Vec<u8>>;

    #[inline]
    fn test<T: Input<Result<bool, PanicError>>>(
        &mut self,
        input: &mut T,
    ) -> Result<bool, PanicError> {
        input.with_slice(&mut |slice| {
            panic::catch(|| {
                let res = (self.fun)(slice);
                match res.into_result() {
                    Ok(()) => Ok(true),
                    Err(err) => Err(err),
                }
            })
        })
    }

    #[inline]
    fn generate_value<T: Input<Self::Value>>(&self, input: &mut T) -> Self::Value {
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
    Ret: IntoResult,
{
    type Value = SliceDebug<Vec<u8>>;

    #[inline]
    fn test<T: Input<Result<bool, PanicError>>>(
        &mut self,
        input: &mut T,
    ) -> Result<bool, PanicError> {
        input.with_slice(&mut |slice| {
            panic::catch(|| {
                let input = slice.to_vec();
                let res = (self.fun)(input);
                match res.into_result() {
                    Ok(()) => Ok(true),
                    Err(err) => Err(err),
                }
            })
        })
    }

    #[inline]
    fn generate_value<T: Input<Self::Value>>(&self, input: &mut T) -> Self::Value {
        input.with_slice(&mut |slice| SliceDebug(slice.to_vec()))
    }
}

/// Lazily generates a new value for the given driver
#[cfg(not(kani))]
macro_rules! generate_value {
    ($self:ident, $driver:ident) => {{
        let forward_panic = crate::panic::forward_panic(true);
        let value = if let Some(value) = $self.value.as_mut() {
            if $self.gen.mutate($driver, value).is_some() {
                value
            } else {
                crate::panic::forward_panic(forward_panic);
                return Ok(false);
            }
        } else if let Some(value) = $self.gen.generate($driver) {
            $self.value = Some(value);
            $self.value.as_ref().unwrap()
        } else {
            crate::panic::forward_panic(forward_panic);
            return Ok(false);
        };
        crate::panic::forward_panic(forward_panic);
        value
    }};
}
#[cfg(kani)]
macro_rules! generate_value {
    ($self:ident, $driver:ident) => {{
        $self.value = $self.gen.generate($driver);
        kani::assume($self.value.is_some());
        $self.value.as_ref().unwrap()
    }};
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

impl<F: RefUnwindSafe + FnMut(&G::Output) -> Ret, G: ValueGenerator, Ret> Test
    for BorrowedGeneratorTest<F, G, G::Output>
where
    Ret: IntoResult,
    G::Output: core::fmt::Debug,
{
    type Value = G::Output;

    #[inline]
    fn test<T: Input<Result<bool, PanicError>>>(
        &mut self,
        input: &mut T,
    ) -> Result<bool, PanicError> {
        input.with_driver(&mut |driver| {
            let fun = &mut self.fun;

            // The value will not be reused after being captured, so it is unwind safe
            let value = core::panic::AssertUnwindSafe(generate_value!(self, driver));

            panic::catch(|| {
                let res = (fun)(&value);
                match res.into_result() {
                    Ok(()) => Ok(true),
                    Err(err) => Err(err),
                }
            })
        })
    }

    #[inline]
    fn generate_value<T: Input<Self::Value>>(&self, input: &mut T) -> Self::Value {
        input.with_driver(&mut |driver| {
            let forward_panic = crate::panic::forward_panic(true);
            let value = self.gen.generate(driver).unwrap();
            crate::panic::forward_panic(forward_panic);
            value
        })
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

impl<F: RefUnwindSafe + FnMut(G::Output) -> Ret, G: ValueGenerator, Ret> Test
    for ClonedGeneratorTest<F, G, G::Output>
where
    Ret: IntoResult,
    G::Output: core::fmt::Debug + Clone + core::panic::RefUnwindSafe,
{
    type Value = G::Output;

    #[inline]
    fn test<T: Input<Result<bool, PanicError>>>(
        &mut self,
        input: &mut T,
    ) -> Result<bool, PanicError> {
        input.with_driver(&mut |driver| {
            let fun = &mut self.fun;

            let value = generate_value!(self, driver);

            #[cfg(kani)]
            let input = {
                let _ = value;
                self.value.take().unwrap()
            };

            #[cfg(not(kani))]
            let input = value.clone();

            // The value will not be reused after being captured, so it is unwind safe
            let input = core::panic::AssertUnwindSafe(input);

            panic::catch(move || {
                let core::panic::AssertUnwindSafe(input) = input;
                let res = (fun)(input);
                match res.into_result() {
                    Ok(()) => Ok(true),
                    Err(err) => Err(err),
                }
            })
        })
    }

    #[inline]
    fn generate_value<T: Input<Self::Value>>(&self, input: &mut T) -> Self::Value {
        input.with_driver(&mut |driver| {
            let forward_panic = crate::panic::forward_panic(true);
            let value = self.gen.generate(driver).unwrap();
            crate::panic::forward_panic(forward_panic);
            value
        })
    }
}

pub struct OnFailure<T, F> {
    test: T,
    on_failure: F,
}

impl<T, F> OnFailure<T, F> {
    pub fn new(test: T, on_failure: F) -> Self {
        Self { test, on_failure }
    }
}

impl<Tst, F> Test for OnFailure<Tst, F>
where
    Tst: Test,
    F: FnMut(Failure<Tst::Value>),
{
    type Value = Tst::Value;

    #[inline]
    fn test<T: Input<Result<bool, panic::PanicError>>>(
        &mut self,
        input: &mut T,
    ) -> Result<bool, panic::PanicError> {
        self.test.test(input)
    }

    #[inline]
    fn generate_value<T: Input<Self::Value>>(&self, input: &mut T) -> Self::Value {
        self.test.generate_value(input)
    }

    #[inline]
    fn shrink<I: crate::shrink::Input>(
        &mut self,
        input: I,
        seed: Option<Seed>,
        options: &driver::Options,
    ) -> Option<Failure<Self::Value>> {
        self.test.shrink(input, seed, options)
    }

    #[inline]
    fn on_failure(&mut self, failure: Failure<Self::Value>) {
        (self.on_failure)(failure);
    }
}

impl<Tst> Test for OnFailure<Tst, ()>
where
    Tst: Test,
{
    type Value = Tst::Value;

    #[inline]
    fn test<T: Input<Result<bool, panic::PanicError>>>(
        &mut self,
        input: &mut T,
    ) -> Result<bool, panic::PanicError> {
        self.test.test(input)
    }

    #[inline]
    fn generate_value<T: Input<Self::Value>>(&self, input: &mut T) -> Self::Value {
        self.test.generate_value(input)
    }

    #[inline]
    fn shrink<I: crate::shrink::Input>(
        &mut self,
        input: I,
        seed: Option<Seed>,
        options: &driver::Options,
    ) -> Option<Failure<Self::Value>> {
        self.test.shrink(input, seed, options)
    }
}
