#[macro_use]
pub mod collections;

pub use collections::CollectionMutator;

pub mod boxed;
pub mod string;
pub mod sync;

use crate::{Driver, TypeGenerator, ValueGenerator};
pub use alloc::{
    borrow::{Cow, ToOwned},
    collections::{BTreeMap, BTreeSet, BinaryHeap, LinkedList, VecDeque},
    vec::Vec,
};

pub(crate) const DEFAULT_LEN_RANGE: core::ops::RangeInclusive<usize> = 0..=64;

impl_values_collection_generator!(BinaryHeap, BinaryHeapGenerator, DEFAULT_LEN_RANGE, [Ord]);

#[test]
fn binary_heap_test() {
    let _ = generator_test!(gen::<BinaryHeap<u8>>());
}

impl<T: Ord> CollectionMutator for BinaryHeap<T> {
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
        let prev = core::mem::replace(self, BinaryHeap::new());

        for mut item in prev.into_iter().take(new_len) {
            item_gen.mutate(driver, &mut item)?;
            self.push(item);
        }

        for _ in 0..(new_len - self.len()) {
            self.push(item_gen.generate(driver)?);
        }

        Some(())
    }
}

impl_values_collection_generator!(BTreeSet, BTreeSetGenerator, DEFAULT_LEN_RANGE, [Ord]);

#[test]
fn btree_set_test() {
    let _ = generator_test!(gen::<BTreeSet<u8>>());
}

impl<T: Ord> CollectionMutator for BTreeSet<T> {
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
        let prev = core::mem::replace(self, BTreeSet::new());
        for mut item in prev.into_iter().take(new_len) {
            item_gen.mutate(driver, &mut item)?;
            self.insert(item);
        }

        for _ in 0..(new_len - self.len()) {
            self.insert(item_gen.generate(driver)?);
        }

        // We can run into issues where there aren't enough
        // unique values being generated to fill the set.
        if self.len() == new_len {
            return None;
        }

        Some(())
    }
}

impl_values_collection_generator!(LinkedList, LinkedListGenerator, DEFAULT_LEN_RANGE);

#[test]
fn linked_list_test() {
    let _ = generator_test!(gen::<LinkedList<u8>>());
}

impl<T> CollectionMutator for LinkedList<T> {
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
        let to_mutate = self.len().min(new_len);

        for _ in to_mutate..self.len() {
            self.pop_back().unwrap();
        }

        for item in self.iter_mut() {
            item_gen.mutate(driver, item)?;
        }

        let to_add = new_len.saturating_sub(self.len());
        for _ in 0..to_add {
            self.push_back(item_gen.generate(driver)?);
        }

        #[cfg(test)]
        assert_eq!(self.len(), new_len);

        Some(())
    }
}

impl_values_collection_generator!(VecDeque, VecDequeGenerator, DEFAULT_LEN_RANGE);

#[test]
fn vecdeque_test() {
    let _ = generator_test!(gen::<VecDeque<u8>>());
}

impl<T> CollectionMutator for VecDeque<T> {
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
        let to_mutate = self.len().min(new_len);
        self.drain(to_mutate..);
        for item in self.iter_mut() {
            item_gen.mutate(driver, item)?;
        }

        let to_add = new_len.saturating_sub(self.len());
        for _ in 0..to_add {
            self.push_back(item_gen.generate(driver)?);
        }

        #[cfg(test)]
        assert_eq!(self.len(), new_len);

        Some(())
    }
}

impl_values_collection_generator!(Vec, VecGenerator, DEFAULT_LEN_RANGE);

#[test]
fn vec_type_test() {
    let _ = generator_test!(gen::<Vec<u8>>());
}

#[test]
fn vec_with_len_test() {
    let vec: Vec<u8> = generator_test!(gen::<Vec<u8>>().with().len(8usize)).unwrap();
    assert_eq!(vec.len(), 8);
}

#[test]
fn vec_with_values_test() {
    let _ = generator_test!(gen::<Vec<_>>().with().values(4u16..6));
}

#[test]
fn vec_gen_test() {
    let _ = generator_test!({
        let mut vec = Vec::new();
        vec.push(gen::<u8>());
        vec
    });
}

impl<T> CollectionMutator for Vec<T> {
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
        let to_mutate = self.len().min(new_len);
        self.drain(to_mutate..);
        for item in self.iter_mut() {
            item_gen.mutate(driver, item)?;
        }

        let to_add = new_len.saturating_sub(self.len());
        for _ in 0..to_add {
            self.push(item_gen.generate(driver)?);
        }

        #[cfg(test)]
        assert_eq!(self.len(), new_len);

        Some(())
    }
}

impl_key_values_collection_generator!(BTreeMap, BTreeMapGenerator, DEFAULT_LEN_RANGE, [Ord]);

pub type Bytes = Vec<u8>;
pub type BytesGenerator<L> = VecGenerator<crate::TypeValueGenerator<u8>, L>;

pub type Chars = Vec<char>;
pub type CharsGenerator<L> = VecGenerator<crate::TypeValueGenerator<char>, L>;

impl<T> TypeGenerator for Cow<'static, T>
where
    T: ToOwned + ?Sized,
    <T as ToOwned>::Owned: TypeGenerator,
{
    fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
        Some(Cow::Owned(driver.gen()?))
    }
}
