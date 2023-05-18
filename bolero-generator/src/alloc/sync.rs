use crate::{Driver, TypeGenerator};
use alloc::{rc::Rc, sync::Arc};

impl<T: TypeGenerator> TypeGenerator for Arc<T> {
    fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
        driver.gen_recursive(|driver| Some(Self::new(driver.gen()?)))
    }

    fn mutate<D: Driver>(&mut self, driver: &mut D) -> Option<()> {
        driver.gen_recursive(|driver| {
            Arc::get_mut(self)
                .expect("Arc cannot be shared while mutating")
                .mutate(driver)
        })
    }
}

impl<T: TypeGenerator> TypeGenerator for Rc<T> {
    fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
        driver.gen_recursive(|driver| Some(Self::new(driver.gen()?)))
    }

    fn mutate<D: Driver>(&mut self, driver: &mut D) -> Option<()> {
        driver.gen_recursive(|driver| {
            Rc::get_mut(self)
                .expect("Rc cannot be shared while mutating")
                .mutate(driver)
        })
    }
}
