# Private Testing

`bolero` also supports running tests inside of a project. This is useful for testing private interfaces and implementations.

```rust
#[test]
fn my_property_test() {
    bolero::check!()
        .with_type()
        .cloned()
        .for_each(|value: u64| {
            // implement property checks here
        });
}
```
