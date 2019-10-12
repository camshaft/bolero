use crate::{
    gen_bytes, gen_bytes_with_len, BytesGenerator, BytesWithLenGenerator, Rng, TypeGenerator,
    ValueGenerator,
};
use alloc::{string::String, vec::Vec};

pub fn gen_string() -> StringGenerator {
    StringFromVecGenerator(gen_bytes())
}

pub type StringGenerator = StringFromVecGenerator<BytesGenerator>;

pub fn gen_string_with_len<L: ValueGenerator<Output = usize>>(len: L) -> StringWithLenGenerator<L> {
    StringFromVecGenerator(gen_bytes_with_len(len))
}

pub type StringWithLenGenerator<L> = StringFromVecGenerator<BytesWithLenGenerator<L>>;

pub struct StringFromVecGenerator<V>(V);

impl<V: ValueGenerator<Output = Vec<u8>>> ValueGenerator for StringFromVecGenerator<V> {
    type Output = String;

    fn generate<R: Rng>(&mut self, rng: &mut R) -> Self::Output {
        to_string(self.0.generate(rng))
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
    let _ = generator_test!(gen_string());
    let string = generator_test!(gen_string_with_len(32usize));
    assert_eq!(string.len(), 32);
}
