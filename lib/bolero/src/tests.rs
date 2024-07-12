use super::*;

#[test]
#[should_panic]
fn slice_generator_test() {
    check!().for_each(|input| {
        assert!(input.len() > 1000);
    });
}

#[test]
#[should_panic]
fn type_generator_test() {
    check!().with_type().for_each(|input: &u8| {
        assert!(input < &128);
    });
}

#[cfg(feature = "arbitrary")]
#[test]
#[should_panic]
fn arbitrary_generator_test() {
    check!().with_arbitrary().for_each(|input: &u8| {
        assert!(input < &128);
    });
}

#[test]
#[should_panic]
fn type_generator_cloned_test() {
    check!().with_type().cloned().for_each(|input: u8| {
        assert!(input < 128);
    });
}

#[test]
fn range_generator_test() {
    check!().with_generator(0..=5).for_each(|_input: &u8| {
        // println!("{:?}", input);
    });
}

#[test]
fn range_generator_cloned_test() {
    check!()
        .with_generator(0..=5)
        .cloned()
        .for_each(|_input: u8| {
            // println!("{:?}", input);
        });
}

#[test]
fn nested_test() {
    check!().with_generator(0..=5).for_each(|_input: &u8| {
        // println!("{:?}", _input);
    });
}

#[test]
fn iteration_number() {
    // Atomic to avoid having to think about unwind safety
    use std::sync::atomic::Ordering;
    let num_iters = std::sync::atomic::AtomicUsize::new(0);
    check!().with_iterations(5).for_each(|_| {
        num_iters.fetch_add(1, Ordering::Relaxed);
    });
    assert_eq!(num_iters.load(Ordering::Relaxed), 5);
}

#[test]
fn with_test_time() {
    // Atomic to avoid having to think about unwind safety
    use std::sync::atomic::Ordering;
    let num_iters = std::sync::atomic::AtomicUsize::new(0);
    check!()
        .with_test_time(core::time::Duration::from_millis(5))
        .for_each(|_| {
            num_iters.fetch_add(1, Ordering::Relaxed);
        });
    assert!(num_iters.load(Ordering::Relaxed) > 10);
}

#[test]
fn on_failure_generator_test() {
    let mut failures = 0usize;
    check!()
        .with_type()
        .on_failure(|_failure| {
            failures += 1;
        })
        .for_each(|_: &u32| {
            panic!();
        });

    assert!(failures > 1);
}

#[test]
fn on_failure_generator_cloned_test() {
    let mut failures = 0usize;
    check!()
        .with_type()
        .cloned()
        .on_failure(|_failure| {
            failures += 1;
        })
        .for_each(|_: u32| {
            panic!();
        });

    assert!(failures > 1);
}

/*
 * TODO
#[test]
fn on_failure_bytes_test() {
    let mut failures = 0usize;
    check!()
        .on_failure(|_failure| {
            failures += 1;
        })
        .for_each(|_: &[u8]| {
            panic!();
        });

    assert!(failures > 1);
    panic!();
}
*/
