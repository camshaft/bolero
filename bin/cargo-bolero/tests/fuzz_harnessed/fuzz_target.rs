#[test]
fn harnessed_fuzzer() {
    bolero::check!().for_each(|_| {});
}
