# Unit/Property Testing

`bolero` also supports property tests inside of the project with the `check!` call:

```rust
#[test]
fn my_property() {
    bolero::check!()
        .with_type()
        .cloned()
        .with_iterations(1000) // Defaults to 1000
        .for_each(|value: u64| {
            // implement property checks here
        });
}
```

A RNG engine will be used instead of a fuzzing engine in this mode.

Consider the trade-offs when trying to choose between the `fuzz` or `check` modes:

|         | Unit tests | Integration tests | Code coverage guided tests |     Deterministic       |  C/C++ Dependency |
|:-------:|:----------:|:-----------------:|:--------------------------:|:-----------------------:|:-----------------:|
|   fuzz! |      x     |         ✓         |              ✓             |     ✓ (Corpus tests)    |         ✓         |
|  check! |      ✓     |         ✓         |              x             | - (Only with same seed) |         x         |
