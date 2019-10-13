use crate::{Rng, TypeGenerator};
use alloc::{
    borrow::{Cow, ToOwned},
    boxed::Box,
    string::String,
    vec::Vec,
};

impl<T: TypeGenerator> TypeGenerator for Box<T> {
    fn generate<R: Rng>(rng: &mut R) -> Self {
        Box::new(rng.gen())
    }
}

impl<T: TypeGenerator> TypeGenerator for Box<[T]> {
    fn generate<R: Rng>(rng: &mut R) -> Self {
        rng.gen::<Vec<T>>().into_boxed_slice()
    }
}

impl TypeGenerator for Box<str> {
    fn generate<R: Rng>(rng: &mut R) -> Self {
        rng.gen::<String>().into_boxed_str()
    }
}

impl<T> TypeGenerator for Cow<'static, T>
where
    T: ToOwned + ?Sized,
    <T as ToOwned>::Owned: TypeGenerator,
{
    fn generate<R: Rng>(rng: &mut R) -> Self {
        Cow::Owned(rng.gen())
    }
}
