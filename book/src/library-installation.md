# Library Installation

`bolero` is on `crates.io` and can be added to a project's dev dependencies like so:

```shell
$ cargo add --dev bolero
```

Then, create the `fuzz` profile: (Note that LTO is not well-supported for the fuzzing profile)
```toml
[profile.fuzz]
inherits = "dev"
opt-level = 3
incremental = false
codegen-units = 1
```

If you forget adding the profile, then you will get the following error:
```
error: profile `fuzz` is not defined
```

## Structured Test Generation

If your crate wishes to implement structured test generation on public data structures, `bolero-generator` can be added to the main dependencies:
```shell
$ cargo add bolero-generator
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
