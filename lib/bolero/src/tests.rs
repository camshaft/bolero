use super::*;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

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
    let num_iters = AtomicUsize::new(0);
    check!().with_iterations(5).for_each(|_| {
        num_iters.fetch_add(1, Ordering::Relaxed);
    });
    assert_eq!(num_iters.load(Ordering::Relaxed), 5);
}

#[test]
fn with_test_time() {
    // Atomic to avoid having to think about unwind safety
    let num_iters = AtomicUsize::new(0);
    check!()
        .with_test_time(core::time::Duration::from_millis(5))
        .for_each(|_| {
            num_iters.fetch_add(1, Ordering::Relaxed);
        });
    assert!(num_iters.load(Ordering::Relaxed) > 10);
}

#[test]
fn with_exhaustive() {
    let num_iters = AtomicUsize::new(0);
    let total_value = AtomicUsize::new(0);

    check!()
        .with_type::<u8>()
        .cloned()
        .exhaustive()
        .for_each(|value| {
            num_iters.fetch_add(1, Ordering::Relaxed);
            total_value.fetch_add(value as _, Ordering::Relaxed);
        });

    assert_eq!(num_iters.load(Ordering::Relaxed), 256);
    assert_eq!(total_value.load(Ordering::Relaxed), (0..=255).sum());
}

#[test]
#[should_panic]
fn with_exhaustive_failure() {
    check!()
        .with_type::<(u8, u8)>()
        .cloned()
        .exhaustive()
        .for_each(|(a, b)| {
            let _ = a.checked_add(b).unwrap();
        });
}

#[test]
fn with_shrinking() {
    let last_seen_value = AtomicU8::new(0);

    std::panic::catch_unwind(|| {
        check!()
            .with_generator(produce::<u8>())
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
    let max_seen_value = AtomicU8::new(0);
    let n = 20; // P(false negative) = 1/(256^n) assuming uniform gen::<u8>

    for _ in 0..n {
        let last_seen_value = AtomicU8::new(0);

        std::panic::catch_unwind(|| {
            check!()
                .with_generator(produce::<u8>())
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

#[test]
fn scope_test() {
    let runs = AtomicUsize::new(0);

    check!().run(|| {
        let _: u64 = any();
        runs.fetch_add(1, Ordering::Relaxed);
    });

    assert_ne!(runs.load(Ordering::Relaxed), 0);
}

#[test]
#[should_panic]
fn scope_panic_test() {
    check!().run(|| {
        assert!(any::<bool>(), "oops");
    });
}

#[test]
fn scope_exhaustive_test() {
    let runs = AtomicUsize::new(0);

    check!().exhaustive().run(|| {
        let _: u8 = any();
        runs.fetch_add(1, Ordering::Relaxed);
    });

    assert_eq!(runs.load(Ordering::Relaxed), 256);
}

#[test]
#[should_panic]
fn scope_exhaustive_panic_test() {
    check!().exhaustive().run(|| {
        assert!(any::<bool>(), "oops");
    });
}
