pub fn run(a: u8, b: u8) -> u8 {
    if a == 4 && b == 5 && std::env::var("SHOULD_PANIC").is_ok() {
        panic!("it found me");
    }

    0
}

#[test]
fn bolero_test() {
    bolero::check!().with_type().cloned().for_each(|(a, b)| {
        run(a, b);
    });
}
