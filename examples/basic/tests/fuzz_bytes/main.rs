use basic::add;
use bolero::fuzz;
use std::env;

fuzz!(|input| {
    if input.len() < 2 {
        if env::var("SHOULD_PANIC").is_ok() {
            panic!("UH OH...");
        } else {
            return;
        }
    }

    let a = input[0];
    let b = input[1];
    assert!(add(a, b) >= a);
});
