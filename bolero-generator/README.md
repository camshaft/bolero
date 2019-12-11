# bolero-generator

value generator for testing and fuzzing

## Installation

`bolero-generator` is on `crates.io` and can be added to a project like so:

```toml
[dependencies]
bolero-generator = "0.4"
```

## Usage

### Simple type generator

```rust
use bolero_generator::{gen, driver::FuzzDriver, ValueGenerator};
let input = &[1, 2, 3, 4, 5];
let driver = FuzzDriver::new(&input);

let value = gen::<u8>().generate(&mut driver).unwrap();
```

### Parameterized value generator

```rust
use bolero_generator::{gen, driver::FuzzDriver, ValueGenerator};
let input = &[1, 2, 3, 4, 5];
let driver = FuzzDriver::new(&input);

let value = gen::<u8>().with().bounds(5..=42).generate(&mut driver).unwrap();
```

### Nested parameterized value generator

```rust
use bolero_generator::{gen, driver::FuzzDriver, ValueGenerator};
let input = &[1, 2, 3, 4, 5];
let driver = FuzzDriver::new(&input);

let value = (
    gen::<u8>(),
    gen::<u8>()
        .with()
        .bounds(5..=42), // between 5 and including 42
    gen::<Vec<u32>>()
        .with()
        .len(6usize) // always have 6 values
        .values(7..500), // between 7 and 500
).generate(&mut driver).unwrap();
```

### Value modifications with `map` and `and_then`

```rust
use bolero_generator::{gen, driver::FuzzDriver, ValueGenerator};
let input = &[1, 2, 3, 4, 5];
let driver = FuzzDriver::new(&input);

let value = gen::<u8>()
    .map(|value| value / 2)
    .and_then(|value| gen::<Vec<u8>>().with().len(value as usize))
    .generate(&mut driver)
    .unwrap()
```

## Prior work

### [arbitrary](https://github.com/nagisa/rust_arbitrary)

While `bolero` draws a lot of inspiration from the `rust_arbitrary` crate, several improvements were added:

#### Parameterized generation

Arbitrary supports basic value generation, given a type:

```rust
let driver = RingBuffer::new(input, 20).unwrap();
let value: u8 = Arbitrary::arbitrary(&mut driver).unwrap();
```

This can be limiting when constraints need to be applied to the type:

```rust
let driver = RingBuffer::new(input, 20).unwrap();
let value: u8 = Arbitrary::arbitrary(&mut driver).unwrap();
// make sure `value` in between 8 and 20
let value = (value % (20 - 8)) + 8;
```

The same issue arises from [container sizes](https://github.com/nagisa/rust_arbitrary/blob/f077e8c4017dab7e6d9ea4c5148b6b19b0588ecd/src/lib.rs#L42) being limited to 0-255:

```rust
let driver = RingBuffer::new(input, 20).unwrap();
let mut value: Vec<u8> = Arbitrary::arbitrary(&mut driver).unwrap();
// make sure `value` has at least 3 items
while value.len() < 3 {
    value.push(Arbitrary::arbitrary(&mut driver).unwrap());
}
// make sure `value` has no more than 42 items
while value.len() > 42 {
    value.pop();
}
```

`bolero` supports value generation, given a type:

```rust
let driver = FuzzDriver::new(&[1, 2, 3, 4, 5]);
let value = gen::<u8>().generate(&mut driver).unwrap();
```

Parameterized generators can be created by calling `with()`

```rust
let driver = FuzzDriver::new(&[1, 2, 3, 4, 5]);
let value = gen::<u8>().with().bounds(8..=20).generate(&mut driver).unwrap();
```

Container sizes can be specified as well:

```rust
let driver = FuzzDriver::new(&[1, 2, 3, 4, 5]);
let value = gen::<Vec<u8>>().with().len(3usize..=42).generate(&mut driver).unwrap();
```

#### `#![no_std]` compatibility

`bolero` supports environments that require `#![no_std]`.
