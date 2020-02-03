# Getting Started

First create a fuzz target:

```bash
$ cargo bolero new my_fuzz_target
```

This will create a new directory in `tests/my_fuzz_target`, along with a file located at `tests/my_fuzz_target/main.rs`. It will look something like this:

```rust
use bolero::fuzz;

fn main() {
    fuzz!().for_each(|input: &[u8]| {
        // TODO implement checks
        let _ = input;
    });
}

```

`bolero` supports structural testing via the same macro. More information is available in [bolero-generator](https://crates.io/crates/bolero-generator):

```rust
fn main() {
    fuzz!()
        .with_type()
        .cloned()
        .for_each(|(a, b, c): (u8, u16, u32)| {
            if a == 0 && b == 1 && c == 2 {
                panic!("you found me!");
            }
        });
}
```

Value generation can be customized even further by passing a [`ValueGenerator`](https://docs.rs/bolero/latest/bolero/generator/trait.ValueGenerator.html):

```rust
fn main() {
    fuzz!()
        .with_generator(2..42)
        .cloned()
        .for_each(|value| {
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
