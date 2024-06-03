use crate::{driver::Driver, ValueGenerator};

pub trait CollectionGenerator: Sized {
    type Item;

    fn mutate_collection<D: Driver, G>(
        &mut self,
        driver: &mut D,
        new_len: usize,
        item_gen: &G,
    ) -> Option<()>
    where
        G: ValueGenerator<Output = Self::Item>;
}

#[macro_export]
macro_rules! impl_values_collection_generator {
    ($ty:ident, $generator:ident, $default_len_range:expr $(,[$($params:path),*])?) => {
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

            pub fn len<Gen: $crate::ValueGenerator<Output = usize>>(
                self,
                len: Gen,
            ) -> $generator<V, Gen> {
                $generator {
                    values: self.values,
                    len,
                }
            }

            pub fn map_len<
                Gen: $crate::ValueGenerator<Output = usize>,
                F: Fn(L) -> Gen,
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
                L: $crate::ValueGenerator<Output = usize>,
            > $crate::ValueGenerator for $generator<V, L>
        where $(V::Output: Sized $(+ $params)*, )?
            $ty<V::Output>: 'static,
        {
            type Output = $ty<V::Output>;

            #[inline]
            fn generate<D: $crate::Driver>(&self, driver: &mut D) -> Option<Self::Output> {
                let mut value = driver.cache_get().unwrap_or_else(Self::Output::new);
                match Self::mutate(self, driver, &mut value) {
                    Some(()) => Some(value),
                    None => {
                        self.driver_cache(driver, value);
                        None
                    }
                }
            }

            #[inline]
            fn mutate<D: $crate::Driver>(&self, driver: &mut D, value: &mut Self::Output) -> Option<()> {
                driver.enter_list::<Self::Output, _, _, _>(&self.len, |driver, len| {
                    $crate::alloc_generators::CollectionGenerator::mutate_collection(value, driver, len, &self.values)?;

                    if value.len() != len {
                        None
                    } else {
                        Some(())
                    }
                })

            }

            #[inline]
            fn driver_cache<D: $crate::Driver>(&self, driver: &mut D, value: Self::Output) {
                driver.cache_put(value);
            }
        }

        impl<V: 'static + $crate::TypeGenerator $($( + $params)*)?,> $crate::TypeGenerator for $ty<V> {
            #[inline]
            fn generate<D: $crate::Driver>(driver: &mut D) -> Option<Self> {
                let mut value = driver.cache_get().unwrap_or_else(Self::new);
                match Self::mutate(&mut value, driver) {
                    Some(()) => Some(value),
                    None => {
                        value.driver_cache(driver);
                        None
                    }
                }
            }

            #[inline]
            fn mutate<D: $crate::Driver>(&mut self, driver: &mut D) -> Option<()> {
                driver.enter_list::<Self, _, _, _>(&$default_len_range, |driver, len| {
                    $crate::alloc_generators::CollectionGenerator::mutate_collection(self, driver, len, &V::gen())?;

                    if self.len() != len {
                        None
                    } else {
                        Some(())
                    }
                })
            }

            #[inline]
            fn driver_cache<D: $crate::Driver>(self, driver: &mut D) {
                driver.cache_put(self);
            }
        }

        impl<V: 'static + $crate::TypeGenerator $($( + $params)*)?,> $crate::TypeGeneratorWithParams for $ty<V> {
            type Output =
                $generator<$crate::TypeValueGenerator<V>, core::ops::RangeInclusive<usize>>;

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

            #[inline]
            fn generate<D: $crate::Driver>(&self, driver: &mut D) -> Option<Self::Output> {
                assert!(!self.is_empty(), "cannot generate values from an empty collection");
                let mut value = Self::Output::new();
                Self::mutate(self, driver, &mut value)?;
                Some(value)
            }

            #[inline]
            fn mutate<D: $crate::Driver>(&self, driver: &mut D, value: &mut Self::Output) -> Option<()> {
                driver.enter_list::<Self::Output, _, _, _>(&$default_len_range, |driver, len| {
                    // TODO remove the allocation here
                    let generators: $crate::alloc_generators::Vec<_> = self.iter().collect();
                    let gen_item = $crate::one_of(&generators[..]);

                    $crate::alloc_generators::CollectionGenerator::mutate_collection(value, driver, len, &gen_item)?;

                    // The value generator may have not produced enough unique
                    // values to fill the collection to the desired length.
                    if value.len() != len {
                        None
                    } else {
                        Some(())
                    }
                })
            }
        }
    };
}

#[macro_export]
macro_rules! impl_key_values_collection_generator {
    ($ty:ident, $generator:ident, $default_len_range:expr $(,[$($params:path),*])?) => {
        pub struct $generator<K, V, L> {
            keys: K,
            values: V,
            len: L,
        }

        impl<K: $crate::ValueGenerator, V: $crate::ValueGenerator, L> $generator<K, V, L> {
            pub fn keys<Gen: $crate::ValueGenerator<Output = K::Output>>(
                self,
                keys: Gen,
            ) -> $generator<Gen, V, L> {
                $generator {
                    keys,
                    values: self.values,
                    len: self.len,
                }
            }

            pub fn map_keys<Gen: $crate::ValueGenerator<Output = K::Output>, F: Fn(K) -> Gen>(
                self,
                map: F,
            ) -> $generator<Gen, V, L> {
                $generator {
                    keys: map(self.keys),
                    values: self.values,
                    len: self.len,
                }
            }

            pub fn values<Gen: $crate::ValueGenerator<Output = V::Output>>(
                self,
                values: Gen,
            ) -> $generator<K, Gen, L> {
                $generator {
                    keys: self.keys,
                    values,
                    len: self.len,
                }
            }

            pub fn map_values<Gen: $crate::ValueGenerator<Output = V::Output>, F: Fn(V) -> Gen>(
                self,
                map: F,
            ) -> $generator<K, Gen, L> {
                $generator {
                    keys: self.keys,
                    values: map(self.values),
                    len: self.len,
                }
            }

            pub fn len<Gen: $crate::ValueGenerator<Output = usize>>(
                self,
                len: Gen,
            ) -> $generator<K, V, Gen> {
                $generator {
                    keys: self.keys,
                    values: self.values,
                    len,
                }
            }

            pub fn map_len<
                Gen: $crate::ValueGenerator<Output = usize>,
                F: Fn(L) -> Gen,
            >(
                self,
                map: F,
            ) -> $generator<K, V, Gen> {
                $generator {
                    keys: self.keys,
                    values: self.values,
                    len: map(self.len),
                }
            }
        }

        impl<
                K: $crate::ValueGenerator,
                V: $crate::ValueGenerator,
                L: $crate::ValueGenerator<Output = usize>,
            > $crate::ValueGenerator for $generator<K, V, L>
        $( where K::Output: Sized $(+ $params)*, )?
        {
            type Output = $ty<K::Output, V::Output>;

            #[inline]
            fn generate<D: $crate::Driver>(&self, driver: &mut D) -> Option<Self::Output> {
                driver.enter_list::<Self::Output, _, _, _>(&self.len, |driver, len| {
                    use $crate::ValueGenerator;
                    Iterator::map(0..len, |_| {
                        Some((
                            ValueGenerator::generate(&self.keys, driver)?,
                            ValueGenerator::generate(&self.values, driver)?,
                        ))
                    })
                    .collect()
                })
            }

            // TODO mutate
        }

        impl<K: $crate::TypeGenerator $($( + $params)*)?, V: $crate::TypeGenerator> $crate::TypeGenerator
            for $ty<K, V>
        {
            #[inline]
            fn generate<D: $crate::Driver>(driver: &mut D) -> Option<Self> {
                driver.enter_list::<Self, _, _, _>(&$default_len_range, |driver, len| {
                    Iterator::map(0..len, |_|
                        Some((K::generate(driver)?, V::generate(driver)?))
                    ).collect()
                })
            }

            // TODO mutate
        }

        impl<K: $crate::TypeGenerator $($( + $params)*)?, V: $crate::TypeGenerator> $crate::TypeGeneratorWithParams
            for $ty<K, V>
        {
            type Output = $generator<
                $crate::TypeValueGenerator<K>,
                $crate::TypeValueGenerator<V>,
                core::ops::RangeInclusive<usize>,
            >;

            fn gen_with() -> Self::Output {
                $generator {
                    keys: Default::default(),
                    values: Default::default(),
                    len: $default_len_range,
                }
            }
        }

        impl<V: $crate::ValueGenerator, K: $crate::ValueGenerator> $crate::ValueGenerator
            for $ty<K, V>
        $( where K::Output: Sized $(+ $params)* )?
        {
            type Output = $ty<K::Output, V::Output>;

            #[inline]
            fn generate<D: $crate::Driver>(&self, driver: &mut D) -> Option<Self::Output> {
                driver.enter_list::<Self::Output, _, _, _>(&$default_len_range, |driver, len| {
                    use $crate::ValueGenerator;

                    assert!(!self.is_empty());

                    let generators: $crate::alloc_generators::Vec<_> = self.iter().collect();
                    let generators_len = 0..generators.len();

                    Iterator::map(0..len, |_| {
                        let index = ValueGenerator::generate(&generators_len, driver)?;
                        let (key, value) = generators[index];
                        Some((
                            ValueGenerator::generate(key, driver)?,
                            ValueGenerator::generate(value, driver)?,
                        ))
                    })
                    .collect()
                })
            }

            // TODO mutate
        }
    };
}
