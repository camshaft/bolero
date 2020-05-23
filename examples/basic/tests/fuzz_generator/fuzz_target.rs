use basic::add;
use bolero::{fuzz, generator::*};

fn main() {
    let should_panic = std::env::var("SHOULD_PANIC").is_ok();

    fuzz!()
        .with_generator((0..254).map_gen(|a: u8| (a, a + 1)))
        .cloned()
        .for_each(|(a, b)| {
            assert!(add(a, b, should_panic) >= a);
        });
}
