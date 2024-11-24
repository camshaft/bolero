use super::*;

fn exhaustive<T: core::fmt::Debug>(name: &str, f: impl Fn() -> T) {
    let driver = crate::driver::exhaustive::Driver::default();
    let driver = crate::driver::object::Object(driver);
    let mut driver = Box::new(driver);

    let mut out = vec![];

    while driver.step().is_continue() {
        driver = scope::with(driver, || {
            out.push(f());
        })
        .0;
    }

    insta::assert_debug_snapshot!(name, out);
}

#[test]
fn any_test() {
    exhaustive("any_test", || (0..4).any())
}

#[test]
fn shuffle_test() {
    exhaustive("shuffle_test", || {
        let mut v = [0, 1, 2];
        v.shuffle();
        v
    })
}

#[test]
fn fill_any_test() {
    exhaustive("fill_any_test", || {
        let mut v = [false, false, false];
        v.fill_any();
        v
    })
}

#[test]
fn pick_test() {
    exhaustive("pick_test", || [1, 2, 3].pick())
}
