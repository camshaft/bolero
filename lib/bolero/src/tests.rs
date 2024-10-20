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
fn with_shrinking() {
    use std::sync::atomic::Ordering;
    let last_seen_value = std::sync::atomic::AtomicU8::new(0);

    std::panic::catch_unwind(|| {
        check!()
            .with_generator(gen::<u8>())
            .with_shrink_time(Duration::from_secs(10))
            .for_each(|value| {
                last_seen_value.store(*value, Ordering::Relaxed);
                assert!(*value == 0)
            });
    })
    .unwrap_err();

    assert_eq!(last_seen_value.load(Ordering::Relaxed), 1);
}

#[test]
fn without_shrinking() {
    use std::sync::atomic::Ordering;

    let max_seen_value = std::sync::atomic::AtomicU8::new(0);
    let n = 20; // P(false negative) = 1/(256^n) assuming uniform gen::<u8>

    for _ in 0..n {
        let last_seen_value = std::sync::atomic::AtomicU8::new(0);

        std::panic::catch_unwind(|| {
            check!()
                .with_generator(gen::<u8>())
                .with_shrink_time(Duration::ZERO)
                .for_each(|value| {
                    last_seen_value.store(*value, Ordering::Relaxed);
                    assert!(*value == 0)
                });
        })
        .unwrap_err();

        let last = last_seen_value.load(Ordering::Relaxed);
        let max = max_seen_value.load(Ordering::Relaxed);

        if last > max {
            max_seen_value.store(last, Ordering::Relaxed);
        }
    }

    assert!(max_seen_value.load(Ordering::Relaxed) > 1);
}
