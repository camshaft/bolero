use crate::{gen, Rng, TypeGenerator, TypedGen, ValueGenerator};
use alloc::vec::Vec;
use core::ops::RangeInclusive;

const DEFAULT_LEN_RANGE: RangeInclusive<usize> = 0..=32;

pub fn gen_vec<V: ValueGenerator>(value: V) -> VecGenerator<V> {
    gen_vec_with_len(value, DEFAULT_LEN_RANGE)
}

pub type VecGenerator<V> = VecWithLenGenerator<V, RangeInclusive<usize>>;

pub fn gen_vec_with_len<V: ValueGenerator, L: ValueGenerator<Output = usize>>(
    value: V,
    len: L,
) -> VecWithLenGenerator<V, L> {
    VecWithLenGenerator { value, len }
}

pub struct VecWithLenGenerator<V, L> {
    value: V,
    len: L,
}

impl<V: ValueGenerator, L: ValueGenerator<Output = usize>> ValueGenerator
    for VecWithLenGenerator<V, L>
{
    type Output = Vec<V::Output>;

    fn generate<R: Rng>(&mut self, rng: &mut R) -> Self::Output {
        let len = self.len.generate(rng);

        let mut value = Vec::with_capacity(len);

        for _ in 0..len {
            value.push(self.value.generate(rng))
        }

        value
    }
}

impl<V: TypeGenerator> TypeGenerator for Vec<V> {
    fn generate<R: Rng>(rng: &mut R) -> Self {
        let len = DEFAULT_LEN_RANGE.generate(rng);

        let mut value = Vec::with_capacity(len);

        for _ in 0..len {
            value.push(V::generate(rng))
        }

        value
    }
}

impl<V: ValueGenerator> ValueGenerator for Vec<V> {
    type Output = Vec<V::Output>;

    fn generate<R: Rng>(&mut self, rng: &mut R) -> Self::Output {
        assert!(!self.is_empty());

        let len = DEFAULT_LEN_RANGE.generate(rng);

        let mut value = Vec::with_capacity(len);
        for _ in 0..len {
            let generator_index = (0..self.len()).generate(rng);
            value.push(self[generator_index].generate(rng))
        }

        value
    }
}

pub fn gen_bytes() -> BytesGenerator {
    gen_vec(gen())
}

pub type BytesGenerator = VecGenerator<TypedGen<u8>>;

pub fn gen_bytes_with_len<L: ValueGenerator<Output = usize>>(len: L) -> BytesWithLenGenerator<L> {
    gen_vec_with_len(gen(), len)
}

pub type BytesWithLenGenerator<L> = VecWithLenGenerator<TypedGen<u8>, L>;

#[test]
fn vec_test() {
    let _ = generator_test!(gen::<Vec<u8>>());
    let _ = generator_test!(gen_vec(gen_u8()));
    let vec = generator_test!(gen_vec_with_len(gen_u8(), 32usize));
    assert_eq!(vec.len(), 32);
    let _ = generator_test!({
        let mut vec = Vec::new();
        vec.push(gen_u8());
        vec
    });
}
