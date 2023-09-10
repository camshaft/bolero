use basic::{add, should_panic};
use bolero::{check, generator::*};

fn main() {
    let should_panic = should_panic();

    check!()
        .with_generator((0..254).map_gen(|a: u8| (a, a + 1)))
        .cloned()
        .for_each(|(a, b)| {
            assert!(add(a, b, should_panic) >= a);
        });
}
