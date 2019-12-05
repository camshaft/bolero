use basic::add;
use bolero::{fuzz, generator::*};

fn main() {
    let generator = (0..10).map_gen(|a: u8| (a, a + 1));

    fuzz!().with_generator(generator).for_each(|(a, b)| {
        assert!(add(a, b) >= a);
    });
}
