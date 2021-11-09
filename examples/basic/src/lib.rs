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

#[cfg(test)]
mod tests {
    use super::*;
    use bolero::{check, generator::*};

    #[test]
    fn add_test() {
        let should_panic = std::env::var("SHOULD_PANIC").is_ok();

        check!()
            .with_generator((0..254).map_gen(|a: u8| (a, a + 1)))
            .cloned()
            .for_each(|(a, b)| {
                assert!(add(a, b, should_panic) >= a);
            });
    }

    #[bolero::test]
    fn add_macro_test(a: &u8, b: &u8) {
        let value = a.saturating_add(b);
        assert!(value >= *a);
        assert!(value >= *b);
    }

    #[test]
    fn other_test() {
        let should_panic = std::env::var("SHOULD_PANIC").is_ok();

        check!()
            .with_generator((0..254).map_gen(|a: u8| (a, a + 1)))
            .cloned()
            .for_each(|(a, b)| {
                assert!(add(a, b, should_panic) >= a);
            });
    }

    #[test]
    fn panicking_generator_test() {
        #[derive(Debug)]
        struct T;

        impl TypeGenerator for T {
            fn generate<R: bolero_generator::Driver>(_: &mut R) -> Option<Self> {
                if std::env::var("SHOULD_PANIC").is_ok() {
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
