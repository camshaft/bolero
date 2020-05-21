# Changelog

## [0.5.0] - 2020-05-21

### Added
- `ValueGenerator` now includes a `mutate` method to improve efficiency
- AFL and honggfuzz can now be included/excluded from `cargo-bolero` with feature flags

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
