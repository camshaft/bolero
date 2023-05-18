#[macro_export]
macro_rules! generator_test {
    ($gen:expr) => {{
        use $crate::{
            driver::{ByteSliceDriver, DriverMode, Options, Rng},
            *,
        };
        let gen = $gen;

        let options = Options::default().with_driver_mode(DriverMode::Forced);

        let mut rng_driver = Rng::new(rand::thread_rng(), &options);

        let inputs = $crate::gen::<Vec<_>>()
            .with()
            .len(1000usize)
            .values($crate::gen::<Vec<u8>>().with().len(0usize..512))
            .generate(&mut rng_driver)
            .unwrap();

        {
            let options = options.clone().with_driver_mode(DriverMode::Direct);
            for input in inputs.iter() {
                if let Some(value) =
                    ValueGenerator::generate(&gen, &mut ByteSliceDriver::new(input, &options))
                {
                    let mut mutated = value.clone();
                    ValueGenerator::mutate(
                        &gen,
                        &mut ByteSliceDriver::new(input, &options),
                        &mut mutated,
                    )
                    .expect("mutation with same driver should produce a value");
                    assert_eq!(
                        value, mutated,
                        "a mutation with the same input should produce the original"
                    );
                }
            }
        }

        // keep track of failed forced inputs and make sure they didn't all fail
        let mut failed_forced = 0;

        for input in inputs.iter() {
            if let Some(value) =
                ValueGenerator::generate(&gen, &mut ByteSliceDriver::new(input, &options))
            {
                let mut mutated = value.clone();
                ValueGenerator::mutate(
                    &gen,
                    &mut ByteSliceDriver::new(input, &options),
                    &mut mutated,
                )
                .expect("mutation with same driver should produce a value");
                assert_eq!(
                    value, mutated,
                    "a mutation with the same input should produce the original"
                );
            } else {
                failed_forced += 1;
            }
        }

        assert_ne!(failed_forced, inputs.len(), "all the forced inputs failed");

        ValueGenerator::generate(&gen, &mut rng_driver)
    }};
}

#[macro_export]
macro_rules! generator_no_clone_test {
    ($gen:expr) => {{
        use $crate::{
            driver::{ByteSliceDriver, DriverMode, Options, Rng},
            *,
        };
        let gen = $gen;

        let options = Options::default().with_driver_mode(DriverMode::Forced);

        let mut rng_driver = Rng::new(rand::thread_rng(), &options);

        let inputs = $crate::gen::<Vec<_>>()
            .with()
            .len(1000usize)
            .values($crate::gen::<Vec<u8>>().with().len(0usize..512))
            .generate(&mut rng_driver)
            .unwrap();

        {
            let options = options.clone().with_driver_mode(DriverMode::Direct);
            for input in inputs.iter() {
                if let Some(mut value) =
                    ValueGenerator::generate(&gen, &mut ByteSliceDriver::new(input, &options))
                {
                    ValueGenerator::mutate(
                        &gen,
                        &mut ByteSliceDriver::new(input, &options),
                        &mut value,
                    )
                    .expect("mutation with same driver should produce a value");
                }
            }
        }

        // keep track of failed forced inputs and make sure they didn't all fail
        let mut failed_forced = 0;

        for input in inputs.iter() {
            if let Some(mut value) =
                ValueGenerator::generate(&gen, &mut ByteSliceDriver::new(input, &options))
            {
                ValueGenerator::mutate(
                    &gen,
                    &mut ByteSliceDriver::new(input, &options),
                    &mut value,
                )
                .expect("mutation with same driver should produce a value");
            } else {
                failed_forced += 1;
            }
        }

        assert_ne!(failed_forced, inputs.len(), "all the forced inputs failed");

        ValueGenerator::generate(&gen, &mut rng_driver)
    }};
}
