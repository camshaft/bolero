use super::*;
use std::time::Duration;

macro_rules! shrink_test_assert {
    ($test:ident, $input:ident, $options:ident, (None)) => {
        assert!(Shrinker::new(&mut $test, $input, None, &$options)
            .shrink()
            .is_none());
    };

    ($test:ident, $input:ident, $options:ident, ($($expected:tt)+)) => {
        let failure = Shrinker::new(&mut $test, $input, None, &$options)
            .shrink()
            .expect("should produce a result");

        assert_eq!(failure.input, $($expected)+);
    };
}

macro_rules! shrink_test {
    ($name:ident, $gen:expr, $input:expr, $duration:expr, ($($expected:tt)+), $check:expr) => {
        #[test]
        fn $name() {
            #[allow(unused_imports)]
            use bolero_generator::{gen, ValueGenerator};

            panic::forward_panic(true);
            panic::capture_backtrace(true);

            let mut test = crate::ClonedGeneratorTest::new($check, $gen);
            let input = ($input).to_vec();

            let options = driver::Options::default().with_shrink_time($duration);

            shrink_test_assert!(test, input, options, ($($expected)+));
        }
    };
}

shrink_test!(
    u16_shrink_test_zero_time,
    gen::<u16>(),
    [255u8; 2],
    Duration::ZERO,
    (None),
    |_| {}
);

shrink_test!(
    u16_shrink_test,
    gen::<u16>(),
    [255u8; 2],
    Duration::from_secs(1),
    (1),
    |value| {
        assert!(value < 20);
        assert!(value % 7 == 0);
    }
);

shrink_test!(
    u32_shrink_test,
    gen::<u32>(),
    [255u8; 4],
    Duration::from_secs(1),
    (20),
    |value| {
        assert!(value < 20);
    }
);

shrink_test!(
    vec_shrink_test,
    gen::<Vec<u32>>().filter_gen(|vec| vec.len() >= 3),
    [255u8; 256],
    Duration::from_secs(1),
    (vec![4, 0, 0]),
    |value: Vec<u32>| {
        assert!(value[0] < 4);
        assert!(value[1] < 5);
        assert!(value[2] < 6);
    }
);

shrink_test!(
    non_start_vec_shrink_test,
    gen::<Vec<u32>>().filter_gen(|vec| vec.len() >= 3),
    [255u8; 256],
    Duration::from_secs(1),
    (vec![0, 5, 0]),
    |value: Vec<u32>| {
        assert!(value[1] < 5);
        assert!(value[2] < 6);
    }
);

shrink_test!(
    middle_vec_shrink_test,
    gen::<Vec<u8>>().filter_gen(|vec| vec.len() >= 3),
    [255u8; 256],
    Duration::from_secs(1),
    (vec![1, 1, 1]),
    |value: Vec<u8>| {
        if value[0] > 0 && *value.last().unwrap() > 0 {
            assert_eq!(value[1], 0);
        }
    }
);
