pub fn run(a: u8, b: u8) -> u8 {
    if a == 1 && b == 2 && std::env::var("SHOULD_PANIC").is_ok() {
        panic!("it found me");
    }

    0
}

#[test]
fn bolero_test() {
    bolero::check!().with_type().for_each(|(a, b)| {
        run(a, b);
    });
}
