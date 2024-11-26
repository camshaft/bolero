use crate::{
    alloc_generators::{CollectionGenerator, DEFAULT_LEN_RANGE},
    Driver, TypeGenerator, TypeGeneratorWithParams, TypeValueGenerator, ValueGenerator,
};
use alloc::string::String;
use core::ops::RangeInclusive;

pub struct StringGenerator<C, L> {
    chars: C,
    len: L,
}

impl<C, L> StringGenerator<C, L> {
    pub fn chars<Gen: ValueGenerator<Output = char>>(self, chars: Gen) -> StringGenerator<Gen, L> {
        StringGenerator {
            chars,
            len: self.len,
        }
    }

    pub fn map_chars<Gen: ValueGenerator<Output = char>, F: Fn(C) -> Gen>(
        self,
        map: F,
    ) -> StringGenerator<Gen, L> {
        StringGenerator {
            chars: map(self.chars),
            len: self.len,
        }
    }

    pub fn len<Gen: ValueGenerator<Output = usize>>(self, len: Gen) -> StringGenerator<C, Gen> {
        StringGenerator {
            chars: self.chars,
            len,
        }
    }

    pub fn map_len<Gen: ValueGenerator<Output = usize>, F: Fn(L) -> Gen>(
        self,
        map: F,
    ) -> StringGenerator<C, Gen> {
        StringGenerator {
            chars: self.chars,
            len: map(self.len),
        }
    }
}

impl<G: ValueGenerator<Output = char>, L: ValueGenerator<Output = usize>> ValueGenerator
    for StringGenerator<G, L>
{
    type Output = String;

    fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
        let mut value = String::default();
        self.mutate(driver, &mut value)?;
        Some(value)
    }

    fn mutate<D: Driver>(&self, driver: &mut D, value: &mut Self::Output) -> Option<()> {
        driver.enter_list::<Self::Output, _, _, _>(&self.len, |driver, len| {
            CollectionGenerator::mutate_collection(value, driver, len, &self.chars)
        })
    }
}

impl CollectionGenerator for String {
    type Item = char;

    fn mutate_collection<D: Driver, G>(
        &mut self,
        driver: &mut D,
        new_len: usize,
        item_gen: &G,
    ) -> Option<()>
    where
        G: ValueGenerator<Output = Self::Item>,
    {
        let prev = core::mem::take(self);

        let to_mutate = self.len().min(new_len);
        let to_append = new_len.saturating_sub(to_mutate);

        for mut c in prev.chars().take(to_mutate) {
            item_gen.mutate(driver, &mut c)?;
            self.push(c);
        }

        for _ in 0..to_append {
            self.push(item_gen.generate(driver)?);
        }

        // make sure the char count is correct
        #[cfg(test)]
        assert_eq!(self.chars().count(), new_len);

        Some(())
    }
}

impl TypeGenerator for String {
    fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
        String::gen_with().generate(driver)
    }
}

impl TypeGeneratorWithParams for String {
    type Output = StringGenerator<TypeValueGenerator<char>, RangeInclusive<usize>>;

    fn gen_with() -> Self::Output {
        StringGenerator {
            chars: Default::default(),
            len: DEFAULT_LEN_RANGE,
        }
    }
}

impl ValueGenerator for String {
    type Output = Self;

    fn generate<D: Driver>(&self, _driver: &mut D) -> Option<Self> {
        Some(self.clone())
    }
}

#[test]
fn string_type_test() {
    let _ = generator_test!(gen::<String>());
}

#[test]
fn string_with_test() {
    let results = generator_test!(gen::<String>().with().len(32usize));
    assert!(results.into_iter().any(|s| s.chars().count() == 32));
}
