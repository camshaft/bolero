#![allow(clippy::implicit_hasher)]

use crate::{alloc_generators::CollectionGenerator, Driver, TypeGenerator, ValueGenerator};
use core::{hash::Hash, ops::RangeInclusive};
use std::{
    collections::{HashMap, HashSet},
    sync::Mutex,
};

const DEFAULT_LEN_RANGE: RangeInclusive<usize> = 0..=32;

// TODO support BuildHasher

impl_values_collection_generator!(HashSet, HashSetGenerator, DEFAULT_LEN_RANGE, [Hash, Eq]);

impl<T: Hash + Eq> CollectionGenerator for HashSet<T> {
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

        // mutate the existing items
        for mut item in prev.into_iter().take(new_len) {
            item_gen.mutate(driver, &mut item)?;
            self.insert(item);
        }

        for _ in 0..(new_len - self.len()) {
            self.insert(item_gen.generate(driver)?);
        }

        Some(())
    }
}

#[test]
fn hash_set_type_test() {
    let _ = generator_test!(gen::<HashSet<u8>>());
}

#[test]
fn hash_set_with_len_test() {
    if let Some(set) = generator_test!(gen::<HashSet<u8>>().with().len(8usize)) {
        assert_eq!(set.len(), 8);
    }
}

#[test]
fn hash_set_with_values_test() {
    let _ = generator_test!(gen::<HashSet<_>>().with().values(4u16..6));
}

impl_key_values_collection_generator!(HashMap, HashMapGenerator, DEFAULT_LEN_RANGE, [Hash, Eq]);

#[test]
fn hash_map_type_test() {
    let _ = generator_test!(gen::<HashMap<u8, u8>>());
}

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

#[test]
fn mutex_type_test() {
    let _ = generator_no_clone_test!(gen::<Mutex<u8>>());
}
