# Introduction

Bolero is a fuzzing and property testing framework for Rust programs.

From [Wikipedia](https://en.wikipedia.org/wiki/Fuzzing), fuzzing is described as:

> Fuzzing or fuzz testing is an automated software testing technique that involves providing invalid, unexpected, or random data as inputs to a computer program. The program is then monitored for exceptions such as crashes, failing built-in code assertions, or potential memory leaks.

## Example test

```rust
use bolero::fuzz;

fn main() {
    fuzz!()
        .with_type()
        .cloned()
        .for_each(|(a, b)| {
            add(a, b);
        })
}

fn add(a: u8, b: u8) -> u8 {
    a + b
}
```
