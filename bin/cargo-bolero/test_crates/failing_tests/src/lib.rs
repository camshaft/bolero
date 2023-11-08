#[test]
fn unit_failing() {
    panic!()
}

#[test]
fn unit_bolero() {
    bolero::check!().for_each(|_: &[u8]| {})
}
