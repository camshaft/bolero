#[macro_export]
macro_rules! generator_test {
    ($gen:expr) => {{
        use $crate::{
            driver::{ByteSliceDriver, Options, Rng},
            *,
        };
        let gen = $gen;

        let options = Options::default();

        let mut rng_driver = Rng::new(
            rand::thread_rng(),
            &options.clone().with_max_len(8 * 1024 * 1024),
        );

        let mut results = vec![];

        let inputs = $crate::gen::<Vec<_>>()
            .with()
            .len(1000usize)
            .values($crate::gen::<Vec<u8>>().with().len(0usize..512))
            .generate(&mut rng_driver)
            .unwrap();

        // keep track of failed inputs and make sure they didn't all fail
        let mut failed = 0;

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
                results.push(value);
            } else {
                failed += 1;
            }
        }

        assert_ne!(failed, inputs.len(), "all the inputs failed");

        {
            let mut grammar = $crate::grammar::Driver::default();
            ValueGenerator::generate(&gen, &mut grammar);
            let grammar = grammar.finish();
            let grammar_opts = $crate::grammar::Options {
                max_depth: Some(3),
                ..Default::default()
            };
            dbg!(grammar.estimate_state_space(&grammar_opts));
            dbg!(grammar.estimate_topology(&grammar_opts));

            let topology = grammar.topology(&grammar_opts);

            //assert_eq!(expected_topology, topology.len() as u128, "{topology:#?}");

            let mut selection = $crate::grammar::topology::Selection::default();
            for node in topology.iter() {
                node.select(&mut selection);
                let mut driver = ByteSliceDriver::new(&[], &options);
                let mut driver = selection.with_driver(&mut driver);
                let out = ValueGenerator::generate(&gen, &mut driver);
                if out.is_none() {
                    panic!("selection returned none {selection:#?}");
                }
                dbg!(out);
                selection.clear();
            }
        }

        results
    }};
}

#[macro_export]
macro_rules! generator_no_clone_test {
    ($gen:expr) => {{
        use $crate::{
            driver::{ByteSliceDriver, Options, Rng},
            *,
        };
        let gen = $gen;

        let options = Options::default();

        let mut rng_driver = Rng::new(rand::thread_rng(), &options);

        let inputs = $crate::gen::<Vec<_>>()
            .with()
            .len(1000usize)
            .values($crate::gen::<Vec<u8>>().with().len(0usize..512))
            .generate(&mut rng_driver)
            .unwrap();

        {
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
        let mut failed = 0;

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
                failed += 1;
            }
        }

        assert_ne!(failed, inputs.len(), "all the inputs failed");

        ValueGenerator::generate(&gen, &mut rng_driver)
    }};
}
