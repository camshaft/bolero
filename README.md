# bolero

fuzz and property testing framework

## Installation

`bolero` is on `crates.io` and can be added to a project like so:

```toml
[dev-dependencies]
bolero = "0.4"
```

`bolero` includes a test generator library, [`bolero-generator`](https://crates.io/crates/bolero-generator). This is useful for crates wishing to implement generator traits for downstream applications or libraries.

```toml
[dependencies]
bolero-generator = "0.4"
```

`bolero` also provides a CLI program to execute fuzz tests, [`cargo-bolero`](https://crates.io/crates/cargo-bolero). It can be installed globally with cargo:

```bash
$ cargo install -f cargo-bolero
```

## Usage

### Fuzzing

First create a fuzz target:

```bash
$ cargo bolero new my_fuzz_target
```

This will create a new directory in `tests/my_fuzz_target`, along with a file located at `tests/my_fuzz_target/main.rs`. It will look something like this:

```rust
use bolero::fuzz;

fn main() {
    fuzz!().for_each(|input| {
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
    fuzz!().with_type().for_each(|(a, b, c): (u8, u16, u32)| {
        if a == 0 && b == 1 && c == 2 {
            panic!("you found me!");
        }
    });
}
```

Value generation can be customized even further by passing a [`ValueGenerator`](https://docs.rs/bolero/latest/bolero/generator/trait.ValueGenerator.html):

```rust
fn main() {
    fuzz!().with_generator(2..42).for_each(|value| {
        if value == 4 {
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

#### Corpus test replay

After running a fuzz target, a corpus is generated (a set of inputs that trigger unique codepaths). This corpus can be now executed using the standard `cargo test` command. The corpus should either be commited to the project repository or be stored/restored from storage, like S3.

```bash
$ cargo test

     Running target/debug/deps/my_fuzz_target-9b2c2acee51634e0

running 1007 tests
...............................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................
test result: ok. 1007 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

### Property Tests

`bolero` also supports property tests inside of the project with the `check!` call:

```rust
#[test]
fn my_property() {
    bolero::check!()
        .with_type()
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

## Prior work

### [rust-fuzz](https://github.com/rust-fuzz)

While `bolero` draws a lot of inspiration from the `rust-fuzz` organization, several improvements were made over the existing libraries:

#### Unified interface

`rust-fuzz` requires a different interface for each type of fuzzer. There is an [RFC](https://github.com/rust-fuzz/rfcs/pull/1) proposing a fix, but seemingly no progress has been made.

`bolero` unifies the implementation to a single interface that supports `libfuzzer`, `afl`, and `honggfuzz`:

```rust
extern crate your_crate;
use bolero::fuzz;

fn main() {
    fuzz!().for_each(|input| {
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
