# Unit Testing

`bolero` also supports unit tests inside of the project with the `check!` call:

```rust
#[test]
fn my_unit_test() {
    bolero::check!()
        .with_type()
        .cloned()
        .with_iterations(100) // Defaults to 1000
        .for_each(|value: u64| {
            // implement checks here
        });
}
```

A RNG engine will be used instead of a fuzzing engine in this mode. This means the inputs
will not be guided by any instrumentation (coverage, profiling, etc) and instead will be
completely random. This can be OK for quickly checking various random inputs, but will have a harder
time finding tricky edge cases.

Also note that tests may pass on one execution and fail the next because randomized inputs
will not all trigger the same codepaths.

Consider the trade-offs when choosing between the `fuzz` or `check` modes:

|         | Unit tests | Integration tests | Code coverage guided tests |  C/C++ Dependency |
|:-------:|:----------:|:-----------------:|:--------------------------:|:-----------------:|
|   fuzz! |      x     |         ✓         |              ✓             |         ✓         |
|  check! |      ✓     |         ✓         |              x             |         x         |
