use basic::add;
use bolero::fuzz;
use std::env;

fn main() {
    let should_panic = env::var("SHOULD_PANIC").is_ok();

    fuzz!().for_each(|input| {
        if input.len() < 2 {
            return;
        }

        if should_panic {
            assert_ne!(input[0], 123);
        }

        let a = input[0];
        let b = input[1];
        assert!(add(a, b) >= a);
    });
}
