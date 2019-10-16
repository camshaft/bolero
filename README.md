# bolero

fuzz and property testing framework

## Installation

`bolero` is on `crates.io` and can be added to a project like so:

```toml
[dev-dependencies]
bolero = "0.1"
```

`bolero` includes a test generator library, [`bolero-generator`](https://crates.io/crates/bolero-generator). This is useful for crates wishing to implement generator traits for downstream applications or libraries. It is `#![no_std]` compatible and can be included as a regular dependency.

```toml
[dependencies]
bolero-generator = "0.1"
```

`std` support can be enabled if needed:

```toml
[dependencies]
bolero-generator = { version = "0.1", features = ["std"] }
```

`bolero` also provides a CLI program to execute fuzz tests, [`cargo-bolero`](https://crates.io/crates/cargo-bolero). It can be installed globally with cargo:

```bash
$ cargo install bolero-cargo
```

## Usage

### Setup

First create a fuzz target:

```bash
$ cargo bolero new my_fuzz_target
```

This will create a new directory in `tests/my_fuzz_target`, along with a file located at `tests/my_fuzz_target/main.rs`. It will look something like this:

```rust
use bolero::fuzz;

fn main() {
    fuzz!(|input| {
        if input.len() < 3 {
            return;
        }

        if input[0] == 0 && input[1] == 1 && input[2] == 2 {
            panic!("you found me!");
        }
    });
}
```

`bolero` supports property testing via the same macro. More information is available in [bolero-generator](https://crates.io/crates/bolero-generator):

```rust
fn main() {
    fuzz!(for (a, b, c) in gen() {
        if a == 0 && b == 1 && c == 2 {
            panic!("you found me!");
        }
    });
}
```

The fuzz target can now be executed:

```bash
$ cargo bolero fuzz my_fuzz_target --fuzzer libfuzzer --sanitizer address
```

`bolero` supports [`libfuzzer`](https://llvm.org/docs/LibFuzzer.html), [`afl`](http://lcamtuf.coredump.cx/afl/), and [`honggfuzz`](https://google.github.io/honggfuzz/) via the `fuzzer` argument.

### Corpus test replay

After running a fuzz target, a corpus is generated (a set of inputs that trigger unique codepaths). This corpus can be now executed using the standard `cargo test` command. The corpus should either be commited to the project repository or be stored/restored from storage, like S3.

```bash
$ cargo test

     Running target/debug/deps/my_fuzz_target-9b2c2acee51634e0

running 4 tests
test corpus/3f6089c3d3533d52fe8fbc49624a9b584fe49bd7 ... ok
test corpus/7e2e044376b5b655c8a7d1df734f00ab070c8b68 ... ok
test corpus/85e53271e14006f0265921d02d4d736cdc580b0b ... ok
test corpus/72d2d4ef5fc0e8e338eeb77ef1fc73b5ed96a28f ... ok

test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

## Prior work

### [rust-fuzz](https://github.com/rust-fuzz)

While `bolero` draws a lot of inspiration from the `rust-fuzz` organization, several improvements were made over the existing libraries:

#### Unified interface

`rust-fuzz` requires a different interface for each type of fuzzer. There is an [RFC](https://github.com/rust-fuzz/rfcs/pull/1) proposing a fix, but seemingly no progress has been made:

`libfuzzer`:

```rust
#![no_main]

#[macro_use]
extern crate libfuzzer_sys;
extern crate your_crate;

fuzz_target!(|data: &[u8]| {
    // code to fuzz goes here
});
```

`afl`:

```rust
#[macro_use]
extern crate afl;
extern crate your_crate;

fn main() {
    fuzz!(|data: &[u8]| {
        // code to fuzz goes here
    });
}
```

`honggfuzz`:

```rust
#[macro_use]
extern crate honggfuzz;
extern crate your_crate;

fn main() {
    loop {
        fuzz!(|data: &[u8]| {
            // code to fuzz goes here
        });
    }
}
```

`bolero` unifies the implementation to a single interface that supports `libfuzzer`, `afl`, and `honggfuzz`:

```rust
extern crate your_crate;
use bolero::fuzz;

fn main() {
    fuzz!(|input| {
        // code to fuzz goes here
    });
}
```

Fuzzers can be easily swapped out with the `fuzzer` flag passed to `cargo-bolero`:

```bash
$ cargo bolero fuzz --fuzzer {libfuzzer,afl,honggfuzz} my_fuzz_target
```

#### `cargo test` integration

`bolero` supports running the test corpus derived from the fuzz targets as unit tests. This is automatically done when running `cargo test`. The fuzz targets are also placed in the project in the standard `tests` directory, as opposed to creating a separate crate for fuzz tests, like the `rust-fuzz` crates require.

#### Works in stable Rust

`bolero` does not require nightly to execute fuzz targets in the case a sanitizer has not been specified. Most `rust-fuzz` crates require sanitizers to be enabled, which requires nightly.

```bash
# does not require nightly
$ cargo bolero fuzz my_fuzz_target

# requires nightly
$ cargo bolero fuzz --sanitizer address my_fuzz_target
```
