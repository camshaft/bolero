/// Doctest to make sure it compiles
/// ```
/// assert_eq!(basic::add(1, 2, false), 3);
/// ```
pub fn add(a: u8, b: u8, should_panic: bool) -> u8 {
    if should_panic {
        a + b
    } else {
        a.saturating_add(b)
    }
}

pub fn should_panic() -> bool {
    if cfg!(bolero_should_panic) {
        true
    } else if cfg!(kani) {
        false
    } else {
        std::env::var("SHOULD_PANIC").is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bolero::{check, generator::*};

    #[test]
    #[cfg_attr(kani, kani::proof)]
    fn add_test() {
        let should_panic = should_panic();

        check!()
            .with_generator((0..254).map_gen(|a: u8| (a, a + 1)))
            .cloned()
            .for_each(|(a, b)| {
                assert!(add(a, b, should_panic) >= a);
            });
    }

    #[test]
    #[cfg_attr(kani, kani::proof)]
    fn other_test() {
        let should_panic = should_panic();

        check!()
            .with_generator((0..254).map_gen(|a: u8| (a, a + 1)))
            .cloned()
            .for_each(|(a, b)| {
                assert!(add(a, b, should_panic) >= a);
            });
    }

    #[test]
    #[cfg_attr(kani, kani::proof)]
    fn exhaustive_test() {
        let should_panic = should_panic();

        check!()
            .exhaustive()
            .with_type()
            .cloned()
            .for_each(|(a, b)| assert!(add(a, b, should_panic) >= a));
    }

    #[test]
    #[cfg_attr(kani, kani::proof)]
    fn run_test() {
        let should_panic = should_panic();

        check!().run(|| {
            let a = bolero::any();
            let b = bolero::any();
            assert!(add(a, b, should_panic) >= a)
        });
    }

    #[test]
    #[cfg_attr(kani, kani::proof)]
    fn unit_test() {
        let should_panic = should_panic();

        let a = bolero::any();
        let b = bolero::any();
        assert!(add(a, b, should_panic) >= a);
    }

    #[test]
    fn panicking_generator_test() {
        #[derive(Debug)]
        struct T;

        impl TypeGenerator for T {
            fn generate<R: bolero_generator::Driver>(_: &mut R) -> Option<Self> {
                if should_panic() {
                    panic!("generator panicked!");
                } else {
                    Some(Self)
                }
            }
        }

        check!().with_type::<T>().for_each(|_| {
            // nothing to assert
        })
    }
}
