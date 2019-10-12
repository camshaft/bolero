use crate::{rng::Rng, TypeGenerator, ValueGenerator};

#[derive(Debug)]
pub struct BooleanGenerator {
    weight: f32,
}

impl ValueGenerator for bool {
    type Output = bool;

    fn generate<R: Rng>(&mut self, rng: &mut R) -> Self::Output {
        gen_bool().generate(rng)
    }
}

impl ValueGenerator for BooleanGenerator {
    type Output = bool;

    fn generate<R: Rng>(&mut self, rng: &mut R) -> Self::Output {
        let value = rng.next_u32() as f32 / core::u32::MAX as f32;
        value > self.weight
    }
}

impl TypeGenerator for bool {
    fn generate<R: Rng>(rng: &mut R) -> Self {
        gen_bool().generate(rng)
    }
}

pub fn gen_bool() -> BooleanGenerator {
    gen_bool_weighted(0.5)
}

pub fn gen_bool_weighted(weight: f32) -> BooleanGenerator {
    BooleanGenerator { weight }
}

#[test]
fn bool_test() {
    let _ = generator_test!(gen::<bool>());
    let _ = generator_test!(gen_bool());
    let _ = generator_test!(gen_bool_weighted(0.1));
}
