use crate::{Driver, TypeGenerator};
use alloc::{rc::Rc, sync::Arc};

impl<T: TypeGenerator> TypeGenerator for Arc<T> {
    fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
        Some(Self::new(driver.gen()?))
    }
}

impl<T: TypeGenerator> TypeGenerator for Rc<T> {
    fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
        Some(Self::new(driver.gen()?))
    }
}
