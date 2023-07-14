# Library Installation

`bolero` is on `crates.io` and can be added to a project's dev dependencies like so:

```shell
$ cargo add --dev bolero
```

Or add
```toml
[dev-dependencies]
bolero = "0.8"
```
to `Cargo.toml`.

Then, create the `fuzz` profile:
```toml
[profile.fuzz]
inherits = "release"
codegen-units = 1
debug-assertions = true
```

## Structured Test Generation

If your crate wishes to implement structured test generation on public data structures, `bolero-generator` can be added to the main dependencies:
```shell
$ cargo add bolero-generator
```

```toml
[dependencies]
bolero-generator = "0.8"
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
