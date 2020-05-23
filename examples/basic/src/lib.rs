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
    use bolero::{fuzz, generator::*};

    #[test]
    fn add_test() {
        let should_panic = std::env::var("ADD_SHOULD_PANIC").is_ok();

        fuzz!()
            .with_generator((0..254).map_gen(|a: u8| (a, a + 1)))
            .cloned()
            .for_each(|(a, b)| {
                assert!(add(a, b, should_panic) >= a);
            });
    }

    #[test]
    fn other_test() {
        let should_panic = std::env::var("OTHER_SHOULD_PANIC").is_ok();

        fuzz!()
            .with_generator((0..254).map_gen(|a: u8| (a, a + 1)))
            .cloned()
            .for_each(|(a, b)| {
                assert!(add(a, b, should_panic) >= a);
            });
    }
}
