use crate::ValueGenerator;

pub struct Generator<T: ValueGenerator> {
    inner: T,
    tree: super::Tree,
}

impl<T: ValueGenerator> Generator<T> {
    pub fn new(generator: T, tree: super::Tree) -> Self {
        Self {
            inner: generator,
            tree,
        }
    }
}

impl<T: ValueGenerator> ValueGenerator for Generator<T> {
    type Output = T::Output;

    #[inline]
    fn generate<D: crate::Driver>(&self, driver: &mut D) -> Option<Self::Output> {
        let selection = self.tree.generate(driver)?;
        let res = {
            let mut driver = selection.with_driver(driver);
            self.inner.generate(&mut driver)
        };
        driver.cache_put(selection);
        res
    }

    #[inline]
    fn mutate<D: crate::Driver>(&self, driver: &mut D, output: &mut Self::Output) -> Option<()> {
        let selection = self.tree.generate(driver)?;
        let res = {
            let mut driver = selection.with_driver(driver);
            self.inner.mutate(&mut driver, output)
        };
        driver.cache_put(selection);
        res
    }
}
