use basic::add;
use bolero::{fuzz, generator::*};

fn main() {
    fuzz!()
        .with_generator((0..10).map_gen(|a: u8| (a, a + 1)))
        .for_each(|(a, b)| {
            assert!(add(a, b) >= a);
        });
}
