# Library Installation

`bolero` is on `crates.io` and can be added to a project's dev dependencies like so:

```toml
[dev-dependencies]
bolero = "0.4"
```

## Structured Test Generation

If your crate wishes to implement structured test generation on public data structures, `bolero-generator` can be added to the main dependencies:

```toml
[dependencies]
bolero-generator = "0.4"
```

The derive attribute can now be used:

```rust
#[derive(Debug, bolero_generator::TypeGenerator)]
pub struct Coord3d {
    x: u64,
    y: u64,
    z: u64,
}
```
