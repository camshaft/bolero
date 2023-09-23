use super::*;

#[test]
#[should_panic]
fn slice_generator_test() {
    check!().for_each(|input| {
        assert!(input.len() > 1000);
    });
}

#[test]
#[should_panic]
fn type_generator_test() {
    check!().with_type().for_each(|input: &u8| {
        assert!(input < &128);
    });
}

#[cfg(feature = "arbitrary")]
#[test]
#[should_panic]
fn arbitrary_generator_test() {
    check!().with_arbitrary().for_each(|input: &u8| {
        assert!(input < &128);
    });
}

#[test]
#[should_panic]
fn type_generator_cloned_test() {
    check!().with_type().cloned().for_each(|input: u8| {
        assert!(input < 128);
    });
}

#[test]
fn range_generator_test() {
    check!().with_generator(0..=5).for_each(|_input: &u8| {
        // println!("{:?}", input);
    });
}

#[test]
fn range_generator_cloned_test() {
    check!()
        .with_generator(0..=5)
        .cloned()
        .for_each(|_input: u8| {
            // println!("{:?}", input);
        });
}

#[test]
fn nested_test() {
    check!().with_generator(0..=5).for_each(|_input: &u8| {
        // println!("{:?}", input);
    });
}
