use crate::{rng::Rng, TypeGenerator, TypeGeneratorWithParams, ValueGenerator};

#[derive(Debug)]
pub struct BooleanGenerator {
    weight: f32,
}

impl Default for BooleanGenerator {
    fn default() -> Self {
        Self { weight: 0.5 }
    }
}

impl ValueGenerator for bool {
    type Output = bool;

    fn generate<R: Rng>(&self, _rng: &mut R) -> Self::Output {
        *self
    }
}

impl BooleanGenerator {
    pub fn weight(mut self, weight: f32) -> Self {
        assert!(0.0 <= weight && weight <= 1.0);
        self.weight = weight;
        self
    }
}

impl TypeGeneratorWithParams for bool {
    type Output = BooleanGenerator;

    fn gen_with() -> Self::Output {
        Default::default()
    }
}

impl ValueGenerator for BooleanGenerator {
    type Output = bool;

    fn generate<R: Rng>(&self, rng: &mut R) -> Self::Output {
        let value = rng.gen::<u32>() as f32 / core::u32::MAX as f32;
        value < self.weight
    }
}

impl TypeGenerator for bool {
    fn generate<R: Rng>(rng: &mut R) -> Self {
        BooleanGenerator::default().generate(rng)
    }
}

#[test]
fn bool_test() {
    let _ = generator_test!(gen::<bool>());
    let _ = generator_test!(gen::<bool>().with().weight(0.1));
}
