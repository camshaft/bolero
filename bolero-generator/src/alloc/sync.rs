use crate::{rng::Rng, TypeGenerator};
use alloc::{rc::Rc, sync::Arc};

impl<T: TypeGenerator> TypeGenerator for Arc<T> {
    fn generate<R: Rng>(rng: &mut R) -> Self {
        Self::new(rng.gen())
    }
}

impl<T: TypeGenerator> TypeGenerator for Rc<T> {
    fn generate<R: Rng>(rng: &mut R) -> Self {
        Self::new(rng.gen())
    }
}
