use crate::{Driver, TypeGenerator};
use alloc::{boxed::Box, string::String, vec::Vec};

impl<T: TypeGenerator> TypeGenerator for Box<T> {
    fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
        driver.depth_guard(|driver| Some(Box::new(driver.gen()?)))
    }

    fn mutate<D: Driver>(&mut self, driver: &mut D) -> Option<()> {
        driver.depth_guard(|driver| self.as_mut().mutate(driver))
    }
}

impl<T: TypeGenerator> TypeGenerator for Box<[T]> {
    fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
        Some(driver.gen::<Vec<T>>()?.into_boxed_slice())
    }

    // TODO mutate
}

impl TypeGenerator for Box<str> {
    fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
        Some(driver.gen::<String>()?.into_boxed_str())
    }

    // TODO mutate
}
