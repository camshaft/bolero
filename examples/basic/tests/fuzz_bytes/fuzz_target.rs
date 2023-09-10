use basic::{add, should_panic};
use bolero::check;
use std::env;

fn main() {
    let should_panic = should_panic();

    check!().for_each(|input| {
        if input.len() < 2 {
            return;
        }

        if should_panic {
            assert_ne!(input[0], 123);
        }

        let a = input[0];
        let b = input[1];
        assert!(add(a, b, should_panic) >= a);
    });
}
