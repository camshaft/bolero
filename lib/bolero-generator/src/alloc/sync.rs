use crate::{Driver, TypeGenerator};
use alloc::{rc::Rc, sync::Arc};

impl<T: TypeGenerator> TypeGenerator for Arc<T> {
    fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
        driver.depth_guard(|driver| Some(Self::new(driver.produce()?)))
    }

    fn mutate<D: Driver>(&mut self, driver: &mut D) -> Option<()> {
        driver.depth_guard(|driver| {
            Arc::get_mut(self)
                .expect("Arc cannot be shared while mutating")
                .mutate(driver)
        })
    }
}

impl<T: TypeGenerator> TypeGenerator for Rc<T> {
    fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
        driver.depth_guard(|driver| Some(Self::new(driver.produce()?)))
    }

    fn mutate<D: Driver>(&mut self, driver: &mut D) -> Option<()> {
        driver.depth_guard(|driver| {
            Rc::get_mut(self)
                .expect("Rc cannot be shared while mutating")
                .mutate(driver)
        })
    }
}
