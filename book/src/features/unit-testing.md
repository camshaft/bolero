# Unit/Property Testing

`bolero` also supports tests inside of the project

```rust
#[test]
fn my_property_test() {
    bolero::fuzz!()
        .with_type()
        .cloned()
        .for_each(|value: u64| {
            // implement property checks here
        });
}
```
