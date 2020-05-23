#[macro_export]
macro_rules! generator_test {
    ($gen:expr) => {{
        use $crate::{
            driver::{ByteSliceDriver, ForcedRng},
            *,
        };
        let gen = $gen;

        let mut rng_driver = ForcedRng::new(rand::thread_rng());

        let inputs = $crate::gen::<Vec<_>>()
            .with()
            .len(1000usize)
            .values($crate::gen::<Vec<u8>>().with().len(0usize..512))
            .generate(&mut rng_driver)
            .unwrap();

        for input in inputs.iter() {
            if let Some(mut value) =
                ValueGenerator::generate(&gen, &mut ByteSliceDriver::new_direct(input))
            {
                ValueGenerator::mutate(&gen, &mut ByteSliceDriver::new_direct(input), &mut value);
            }
        }
        for input in inputs.iter() {
            if let Some(mut value) =
                ValueGenerator::generate(&gen, &mut ByteSliceDriver::new_forced(input))
            {
                ValueGenerator::mutate(&gen, &mut ByteSliceDriver::new_forced(input), &mut value);
            }
        }

        ValueGenerator::generate(&gen, &mut rng_driver)
    }};
}

#[macro_export]
macro_rules! generator_mutate_test {
    ($gen:expr) => {{
        use $crate::{
            driver::{ByteSliceDriver, ForcedRng},
            *,
        };
        let gen = $gen;

        let mut rng_driver = ForcedRng::new(rand::thread_rng());

        let inputs = $crate::gen::<Vec<_>>()
            .with()
            .len(1000usize)
            .values($crate::gen::<Vec<u8>>().with().len(0usize..512))
            .generate(&mut rng_driver)
            .unwrap();

        for input in inputs.iter() {
            if let Some(value) =
                ValueGenerator::generate(&gen, &mut ByteSliceDriver::new_direct(input))
            {
                let mut mutated = value.clone();
                ValueGenerator::mutate(&gen, &mut ByteSliceDriver::new_direct(input), &mut mutated);
                assert_eq!(
                    value, mutated,
                    "a mutation with the same input should produce the original"
                );
            }
        }
        for input in inputs.iter() {
            if let Some(value) =
                ValueGenerator::generate(&gen, &mut ByteSliceDriver::new_forced(input))
            {
                let mut mutated = value.clone();
                ValueGenerator::mutate(&gen, &mut ByteSliceDriver::new_forced(input), &mut mutated);
                assert_eq!(
                    value, mutated,
                    "a mutation with the same input should produce the original"
                );
            }
        }

        ValueGenerator::generate(&gen, &mut rng_driver)
    }};
}
