# Changelog

## [0.6.0] - 2020-11-16

### Added

- MSRV set to 1.42.0
- Initial support for executing tests with [MIRI](https://github.com/rust-lang/miri)

### Updated

- libfuzzer is now at version 11.0.0
- afl is now at version v2.57b
- honggfuzz is now at version 2.3.1

### Fixes

- Invalid shrinking transformations could result in an empty panic message
- Test name resolution now relies on `core::any::type_name` instead of backtrace inspection
- Generators that panic could result in an empty panic message

### Breaking Changes

#### Deprecate `fuzz` in favor of more general terms

With the end goal of `bolero` becoming a front-end for various types of execution engines outside of fuzzing (e.g. [crux](https://github.com/camshaft/bolero/issues/34), [seer](https://github.com/dwrensha/seer), [haybale](https://github.com/PLSysSec/haybale), etc) we're deprecating specific language about fuzzing and going for a more general vocabulary.

- The `fuzz!` macro has been deprecated in favor of `check!`
- The `cargo bolero fuzz` command has been deprecated in favor of `cargo bolero test`
- The `--fuzzer` flag has been deprecated in favor of `--engine`

#### Default to `--release` build when testing

In order to achieve a better testing rate, tests are now compiled with `--release`. In order to opt out of this behavior, `--release false` can be passed.

#### Default to `--sanitizer address` when testing

Sanitizers provide additional information to the fuzzing engine which produces better results. This is now the default behavior. In order to opt out of this behavior, `--sanitizer NONE` can be passed.

## [0.5.0] - 2020-05-21

### Added
- `ValueGenerator` now includes a `mutate` method to improve efficiency
- AFL and honggfuzz can now be included/excluded from `cargo-bolero` with feature flags
- AFL updated to 2.56b
- honggfuzz updated to 2.2
- libfuzzer updated to latest release/10.x

#### `libtest` compatibility

Fuzz tests can now be written inside of unit tests

```rust
#[test]
fn my_fuzz_test() {
    fuzz!()
        .with_type()
        .for_each(|value: &Vec<u64>| {
            // implement checks
        })
}
```

### Breaking Changes

#### Generated values must be `cloned`

Fuzz targets must now call `.cloned()` if they wish to take ownership over the generated value, otherwise a reference will be passed.

```rust
// before
fn main() {
    fuzz!()
        .with_type()
        .for_each(|value: Vec<u64>| {
            // implement checks
        })
}
```

```rust
// after
fn main() {
    fuzz!()
        .with_type()
        .for_each(|value: &Vec<u64>| {
            // implement checks
        })
}

// or

fn main() {
    fuzz!()
        .with_type()
        .cloned()
        .for_each(|value: Vec<u64>| {
            // implement checks
        })
}
```

This change makes input iteration quite a bit faster as we're not allocating the generated input everytime.

#### `check!()` has been removed

Because `fuzz!()` is now compatible with `libtest`, `check!()` is no longer needed.
