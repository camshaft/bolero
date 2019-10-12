use crate::{Rng, TypeGenerator, ValueGenerator};
use either::Either;

pub fn gen_result<V: ValueGenerator, E: ValueGenerator>(
    value: V,
    error: E,
) -> ResultGenerator<V, E> {
    ResultGenerator(value, error)
}

pub struct ResultGenerator<V, E>(V, E);

impl<V: ValueGenerator, E: ValueGenerator> ValueGenerator for ResultGenerator<V, E> {
    type Output = Result<V::Output, E::Output>;

    fn generate<R: Rng>(&mut self, rng: &mut R) -> Self::Output {
        if rng.gen() {
            Ok(self.0.generate(rng))
        } else {
            Err(self.1.generate(rng))
        }
    }
}

impl<V: TypeGenerator, E: TypeGenerator> TypeGenerator for Result<V, E> {
    fn generate<R: Rng>(rng: &mut R) -> Self {
        if rng.gen() {
            Ok(rng.gen())
        } else {
            Err(rng.gen())
        }
    }
}

pub fn gen_option<V: ValueGenerator>(value: V) -> OptionGenerator<V> {
    OptionGenerator(value)
}

pub struct OptionGenerator<V>(V);

impl<V: ValueGenerator> ValueGenerator for OptionGenerator<V> {
    type Output = Option<V::Output>;

    fn generate<R: Rng>(&mut self, rng: &mut R) -> Self::Output {
        if rng.gen() {
            Some(self.0.generate(rng))
        } else {
            None
        }
    }
}

impl<V: TypeGenerator> TypeGenerator for Option<V> {
    fn generate<R: Rng>(rng: &mut R) -> Self {
        if rng.gen() {
            Some(rng.gen())
        } else {
            None
        }
    }
}

pub fn gen_either<L: ValueGenerator, R: ValueGenerator>(
    value: L,
    error: R,
) -> ResultGenerator<L, R> {
    ResultGenerator(value, error)
}

pub struct EitherGenerator<L, R>(L, R);

impl<Left: ValueGenerator, Right: ValueGenerator> ValueGenerator for EitherGenerator<Left, Right> {
    type Output = Either<Left::Output, Right::Output>;

    fn generate<R: Rng>(&mut self, rng: &mut R) -> Self::Output {
        if rng.gen() {
            Either::Left(self.0.generate(rng))
        } else {
            Either::Right(self.1.generate(rng))
        }
    }
}

impl<Left: TypeGenerator, Right: TypeGenerator> TypeGenerator for Either<Left, Right> {
    fn generate<R: Rng>(rng: &mut R) -> Self {
        if rng.gen() {
            Either::Left(rng.gen())
        } else {
            Either::Right(rng.gen())
        }
    }
}
