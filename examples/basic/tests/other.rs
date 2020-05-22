use basic::add;
use bolero::{fuzz, generator::*};

#[test]
fn other_integration_test() {
    let should_panic = std::env::var("OTHER_SHOULD_PANIC").is_ok();

    fuzz!()
        .with_generator((0..254).map_gen(|a: u8| (a, a + 1)))
        .cloned()
        .for_each(|(a, b)| {
            assert!(add(a, b, should_panic) >= a);
        });
}

mod nested {
    use super::*;

    #[test]
    fn other_nested_integration_test() {
        let should_panic = std::env::var("OTHER_SHOULD_PANIC").is_ok();

        fuzz!()
            .with_generator((0..254).map_gen(|a: u8| (a, a + 1)))
            .cloned()
            .for_each(|(a, b)| {
                assert!(add(a, b, should_panic) >= a);
            });
    }
}
