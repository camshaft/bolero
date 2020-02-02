#![allow(clippy::implicit_hasher)]

use crate::{alloc_generators::CollectionMutator, Driver, TypeGenerator, ValueGenerator};
use core::{hash::Hash, ops::RangeInclusive};
use std::{
    collections::{HashMap, HashSet},
    sync::Mutex,
};

const DEFAULT_LEN_RANGE: RangeInclusive<usize> = 0..=32;

// TODO support BuildHasher

impl_values_collection_generator!(HashSet, HashSetGenerator, DEFAULT_LEN_RANGE, [Hash, Eq]);

impl<T: Hash + Eq> CollectionMutator for HashSet<T> {
    type Item = T;

    fn mutate_collection<D: Driver, G>(
        &mut self,
        driver: &mut D,
        new_len: usize,
        item_gen: &G,
    ) -> Option<()>
    where
        G: ValueGenerator<Output = Self::Item>,
    {
        let prev = core::mem::replace(self, HashSet::new());
        for mut item in prev.into_iter().take(new_len) {
            item_gen.mutate(driver, &mut item)?;
            self.insert(item);
        }
        while self.len() < new_len {
            self.insert(item_gen.generate(driver)?);
        }
        Some(())
    }
}

impl_key_values_collection_generator!(HashMap, HashMapGenerator, DEFAULT_LEN_RANGE, [Hash, Eq]);

impl<T: TypeGenerator> TypeGenerator for Mutex<T> {
    fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
        Some(Self::new(driver.gen()?))
    }

    fn mutate<D: Driver>(&mut self, driver: &mut D) -> Option<()> {
        if let Ok(mut value) = self.lock() {
            value.mutate(driver)?;
            return Some(());
        }

        *self = Self::generate(driver)?;
        Some(())
    }
}
