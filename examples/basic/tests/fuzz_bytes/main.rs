use basic::add;
use bolero::fuzz;
use std::env;

fn main() {
    let count = 100;

    fuzz!().for_each(|input| {
        if input.len() < 2 {
            if env::var("SHOULD_PANIC").is_ok() {
                panic!("UH OH... {}", count);
            } else {
                return;
            }
        }

        let a = input[0];
        let b = input[1];
        assert!(add(a, b) >= a);
    });
}
