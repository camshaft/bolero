# bolero

fuzzing made easy

## Installation

`bolero` is on `crates.io` and can be added to a project like so:

```toml
[dev-dependencies]
bolero = "0.1"
```

`bolero` also includes a test generator library. It is `#![no_std]` compatible and can be included as a regular dependency, if needed:

```toml
[dependencies]
bolero-generator = "0.1"
```

`std` support can be enabled if needed:

```toml
[dependencies]
bolero-generator = { version = "0.1", features = ["std"] }
```

`bolero` also provides a CLI program to execute fuzz tests. It can be installed with cargo:

```bash
$ cargo install bolero-cargo
```

## Usage

First create a fuzz target:

```bash
$ cargo bolero new my_fuzz_target
```

This will create a new directory in `tests/my_fuzz_target`, along with a file located at `tests/my_fuzz_target/main.rs`. It will look something like this:

```rust
use bolero::fuzz;

fuzz!(|input| {
    if input.len() < 3 {
        return;
    }

    if input[0] == 0 && input[1] == 1 && input[2] == 2 {
        panic!("you found me!");
    }
});
```

The fuzz target can now be tested:

```bash
$ cargo bolero fuzz my_fuzz_target
```
