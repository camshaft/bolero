#[test]
fn integ_failing() {
    panic!()
}

#[test]
fn integ_bolero() {
    bolero::check!().for_each(|_: &[u8]| {})
}