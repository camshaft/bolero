#[macro_use]
pub mod collections;

pub mod boxed;
pub mod string;
pub mod sync;

use alloc::{
    collections::{BTreeMap, BTreeSet, BinaryHeap, LinkedList, VecDeque},
    vec::Vec,
};

const DEFAULT_LEN_RANGE: core::ops::RangeInclusive<usize> = 0..=32;

impl_values_collection_generator!(BinaryHeap, BinaryHeapGenerator, DEFAULT_LEN_RANGE, [Ord]);
impl_values_collection_generator!(BTreeSet, BTreeSetGenerator, DEFAULT_LEN_RANGE, [Ord]);
impl_values_collection_generator!(LinkedList, LinkedListGenerator, DEFAULT_LEN_RANGE);
impl_values_collection_generator!(VecDeque, VecDequeGenerator, DEFAULT_LEN_RANGE);
impl_values_collection_generator!(Vec, VecGenerator, DEFAULT_LEN_RANGE);
impl_key_values_collection_generator!(BTreeMap, BTreeMapGenerator, DEFAULT_LEN_RANGE, [Ord]);

pub type Bytes = Vec<u8>;
pub type BytesGenerator<L> = VecGenerator<crate::TypeValueGenerator<u8>, L>;

#[test]
fn vec_test() {
    let vec = generator_test!(gen::<Vec<u8>>().with().len(8usize));
    assert_eq!(vec.len(), 8);

    let _ = generator_test!(gen::<Vec<_>>().with().values(4u16..6));

    let vec = generator_test!(gen::<Vec<u8>>().with().len(32usize));
    assert_eq!(vec.len(), 32);

    let _ = generator_test!({
        let mut vec = Vec::new();
        vec.push(gen::<u8>());
        vec
    });
}
