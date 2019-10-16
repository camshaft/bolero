# bolero-generator

value generator for testing and fuzzing

## Installation

`bolero-generator` is on `crates.io` and can be added to a project like so:

```toml
[dependencies]
bolero-generator = "0.1"
```

## Usage

### Simple type generator

```rust
use bolero_generator::{gen, rng::FuzzRng, ValueGenerator};
let input = &[1, 2, 3, 4, 5];
let buffer = FuzzRng::new(&input).unwrap();

let value = gen::<u8>().generate(&mut buffer);
```

### Parameterized value generator

```rust
use bolero_generator::{gen, rng::FuzzRng, ValueGenerator};
let input = &[1, 2, 3, 4, 5];
let buffer = FuzzRng::new(&input).unwrap();

let value = gen::<u8>().with().bounds(5..=42).generate(&mut buffer);
```

### Nested parameterized value generator

```rust
use bolero_generator::{gen, rng::FuzzRng, ValueGenerator};
let input = &[1, 2, 3, 4, 5];
let buffer = FuzzRng::new(&input).unwrap();

let value = (
    gen::<u8>(),
    gen::<u8>()
        .with()
        .bounds(5..=42), // between 5 and including 42
    gen::<Vec<u32>>()
        .with()
        .len(6usize) // always have 6 values
        .values(7..500), // between 7 and 500
).generate(&mut buffer);
```

### Value modifications with `map` and `and_then`

```rust
use bolero_generator::{gen, rng::FuzzRng, ValueGenerator};
let input = &[1, 2, 3, 4, 5];
let buffer = FuzzRng::new(&input).unwrap();

let value = gen::<u8>()
    .map(|value| value / 2)
    .and_then(|value| gen::<Vec<u8>>().with().len(value as usize))
    .generate(&mut buffer);
```

## Prior work

### [arbitrary](https://github.com/nagisa/rust_arbitrary)

While `bolero` draws a lot of inspiration from the `rust_arbitrary` crate, several improvements were added:

#### Parameterized generation

Arbitrary supports basic value generation, given a type:

```rust
let buffer = RingBuffer::new(input, 20).unwrap();
let value: u8 = Arbitrary::arbitrary(&mut buffer).unwrap();
```

This can be limiting when constraints need to be applied to the type:

```rust
let buffer = RingBuffer::new(input, 20).unwrap();
let value: u8 = Arbitrary::arbitrary(&mut buffer).unwrap();
// make sure `value` in between 8 and 20
let value = (value % (20 - 8)) + 8;
```

The same issue arises from [container sizes](https://github.com/nagisa/rust_arbitrary/blob/f077e8c4017dab7e6d9ea4c5148b6b19b0588ecd/src/lib.rs#L42) being limited to 0-255:

```rust
let buffer = RingBuffer::new(input, 20).unwrap();
let mut value: Vec<u8> = Arbitrary::arbitrary(&mut buffer).unwrap();
// make sure `value` has at least 3 items
while value.len() < 3 {
    value.push(Arbitrary::arbitrary(&mut buffer).unwrap());
}
// make sure `value` has no more than 42 items
while value.len() > 42 {
    value.pop();
}
```

`bolero` supports value generation, given a type:

```rust
let buffer = FuzzRng::new(&[1, 2, 3, 4, 5]).unwrap();
let value = gen::<u8>().generate(&mut buffer);
```

Parameterized generators can be created by calling `with()`

```rust
let buffer = FuzzRng::new(&[1, 2, 3, 4, 5]).unwrap();
let value = gen::<u8>().with().bounds(8..=20).generate(&mut buffer);
```

Container sizes can be specified as well:

```rust
let buffer = FuzzRng::new(&[1, 2, 3, 4, 5]).unwrap();
let value = gen::<Vec<u8>>().with().len(3usize..=42).generate(&mut buffer);
```

#### `#![no_std]` compatibility

`bolero` supports environments that require `#![no_std]`.
