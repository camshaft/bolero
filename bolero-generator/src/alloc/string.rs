use crate::{BytesGenerator, Rng, TypeGenerator, TypeGeneratorWithParams, ValueGenerator};
use alloc::{string::String, vec::Vec};
use core::ops::RangeInclusive;

pub struct StringGenerator<L>(BytesGenerator<L>);

impl<L> StringGenerator<L> {
    pub fn len<Gen: ValueGenerator<Output = Len>, Len: Into<usize>>(
        self,
        len: Gen,
    ) -> StringGenerator<Gen> {
        StringGenerator(self.0.len(len))
    }

    pub fn map_len<Gen: ValueGenerator<Output = Len>, F: Fn(L) -> Gen, Len: Into<usize>>(
        self,
        map: F,
    ) -> StringGenerator<Gen> {
        StringGenerator(self.0.map_len(map))
    }
}

impl<L: ValueGenerator<Output = Len>, Len: Into<usize>> ValueGenerator for StringGenerator<L> {
    type Output = String;

    fn generate<R: Rng>(&self, rng: &mut R) -> Self::Output {
        to_string(self.0.generate(rng))
    }
}

impl TypeGeneratorWithParams for String {
    type Output = StringGenerator<RangeInclusive<usize>>;

    fn gen_with() -> Self::Output {
        StringGenerator(Vec::gen_with())
    }
}

impl ValueGenerator for String {
    type Output = Self;

    fn generate<R: Rng>(&self, _rng: &mut R) -> Self {
        self.clone()
    }
}

impl TypeGenerator for String {
    fn generate<R: Rng>(rng: &mut R) -> Self {
        to_string(rng.gen())
    }
}

fn to_string(vec: Vec<u8>) -> String {
    String::from_utf8_lossy(&vec).into_owned()
}

#[test]
fn string_test() {
    let _ = generator_test!(gen::<String>());
    let string = generator_test!(gen::<String>().with().len(32usize));
    assert_eq!(string.len(), 32);
}
