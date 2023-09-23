use super::TargetLocation as T;

#[test]
fn item_path_test() {
    let test_name = T::format_symbol_name(__item_path__!());
    assert_eq!(test_name, "target_location::tests::item_path_test");
}

#[test]
fn format_symbol_name_test() {
    assert_eq!(
        T::format_symbol_name("crate::main::__bolero_item_path__::123"),
        "crate"
    );
    assert_eq!(
        T::format_symbol_name("crate::test::__bolero_item_path__::123"),
        "test"
    );
    assert_eq!(
        T::format_symbol_name("crate::test::{{closure}}::__bolero_item_path__::123"),
        "test"
    );
    assert_eq!(
        T::format_symbol_name("crate::nested::test::__bolero_item_path__::123"),
        "nested::test"
    );
}
