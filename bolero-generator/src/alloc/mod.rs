#[macro_export]
macro_rules! impl_values_collection_generator {
    ($ty:ident, $generator:ident, $default_len_range:expr $(, [$($params:path),*])?) => {
        pub struct $generator<V, L> {
            values: V,
            len: L,
        }

        impl<V: $crate::ValueGenerator, L> $generator<V, L> {
            pub fn values<Gen: $crate::ValueGenerator<Output = V::Output>>(
                self,
                values: Gen,
            ) -> $generator<Gen, L> {
                $generator {
                    values,
                    len: self.len,
                }
            }

            pub fn map_values<Gen: $crate::ValueGenerator<Output = V::Output>, F: Fn(V) -> Gen>(
                self,
                map: F,
            ) -> $generator<Gen, L> {
                $generator {
                    values: map(self.values),
                    len: self.len,
                }
            }

            pub fn len<Gen: $crate::ValueGenerator<Output = Len>, Len: Into<usize>>(
                self,
                len: Gen,
            ) -> $generator<V, Gen> {
                $generator {
                    values: self.values,
                    len,
                }
            }

            pub fn map_len<
                Gen: $crate::ValueGenerator<Output = Len>,
                F: Fn(L) -> Gen,
                Len: Into<usize>,
            >(
                self,
                map: F,
            ) -> $generator<V, Gen> {
                $generator {
                    values: self.values,
                    len: map(self.len),
                }
            }
        }

        impl<
                V: $crate::ValueGenerator,
                L: $crate::ValueGenerator<Output = Len>,
                Len: Into<usize>,
        > $crate::ValueGenerator for $generator<V, L>
            $( where V::Output: Sized $(+ $params)*, )?
        {
            type Output = $ty<V::Output>;

            fn generate<R: $crate::Rng>(&self, rng: &mut R) -> Self::Output {
                let len = $crate::ValueGenerator::generate(&self.len, rng).into();
                Iterator::map(0..len, |_| $crate::ValueGenerator::generate(&self.values, rng)).collect()
            }
        }

        impl<V: $crate::TypeGenerator $($( + $params)*)?,> $crate::TypeGenerator for $ty<V> {
            fn generate<R: $crate::Rng>(rng: &mut R) -> Self {
                let len = $crate::ValueGenerator::generate(&$default_len_range, rng);
                Iterator::map(0..len, |_| V::generate(rng)).collect()
            }
        }

        impl<V: $crate::TypeGenerator $($( + $params)*)?,> $crate::TypeGeneratorWithParams for $ty<V> {
            type Output = $generator<$crate::TypeValueGenerator<V>, core::ops::RangeInclusive<usize>>;

            fn gen_with() -> Self::Output {
                $generator {
                    values: Default::default(),
                    len: $default_len_range,
                }
            }
        }

        impl<V: $crate::ValueGenerator> $crate::ValueGenerator for $ty<V>
            $( where V::Output: Sized $(+ $params)* )?
        {
            type Output = $ty<V::Output>;

            fn generate<R: $crate::Rng>(&self, rng: &mut R) -> Self::Output {
                assert!(!self.is_empty());

                let len = $crate::ValueGenerator::generate(&$default_len_range, rng);
                let generators: Vec<_> = self.iter().collect();
                let generators_len = 0..generators.len();

                Iterator::map(0..len, |_| {
                    let index = $crate::ValueGenerator::generate(&generators_len, rng);
                    $crate::ValueGenerator::generate(generators[index], rng)
                }).collect()
            }
        }
    };
}

pub mod r#box;
pub mod string;

pub use r#box::*;
pub use string::*;

use alloc::{
    collections::{BTreeMap, BTreeSet, BinaryHeap, LinkedList, VecDeque},
    vec::Vec,
};

const DEFAULT_LEN_RANGE: core::ops::RangeInclusive<usize> = 0..=32;

impl_values_collection_generator!(BinaryHeap, BinaryheapGenerator, DEFAULT_LEN_RANGE, [Ord]);
impl_values_collection_generator!(BTreeSet, BTreeSetGenerator, DEFAULT_LEN_RANGE, [Ord]);
impl_values_collection_generator!(LinkedList, LinkedListGenerator, DEFAULT_LEN_RANGE);
impl_values_collection_generator!(VecDeque, VecDequeGenerator, DEFAULT_LEN_RANGE);
impl_values_collection_generator!(Vec, VecGenerator, DEFAULT_LEN_RANGE);

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
