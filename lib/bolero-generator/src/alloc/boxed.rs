use crate::{Driver, TypeGenerator};
use alloc::{boxed::Box, string::String, vec::Vec};

impl<T: 'static + TypeGenerator> TypeGenerator for Box<T> {
    #[inline]
    fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
        driver.depth_guard(|driver| {
            if let Some(mut prev) = driver.cache_get::<Self>() {
                match prev.as_mut().mutate(driver) {
                    Some(()) => Some(prev),
                    None => {
                        driver.cache_put(prev);
                        None
                    }
                }
            } else {
                let value = driver.gen()?;
                Some(Box::new(value))
            }
        })
    }

    #[inline]
    fn mutate<D: Driver>(&mut self, driver: &mut D) -> Option<()> {
        driver.depth_guard(|driver| self.as_mut().mutate(driver))
    }

    #[inline]
    fn driver_cache<D: Driver>(self, driver: &mut D) {
        driver.cache_put(self);
    }
}

impl<T: 'static + TypeGenerator> TypeGenerator for Box<[T]> {
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
