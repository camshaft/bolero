# bolero

[![Build Status](https://github.com/camshaft/bolero/workflows/ci/badge.svg)](https://github.com/camshaft/bolero/actions?workflow=ci)
[![Latest version](https://img.shields.io/crates/v/bolero.svg)](https://crates.io/crates/bolero)
[![Documentation](https://docs.rs/bolero/badge.svg)](https://docs.rs/bolero)
[![License](https://img.shields.io/crates/l/bolero.svg)](https://github.com/camshaft/bolero/blob/master/LICENSE)

fuzz and property testing front-end for Rust

## Book

A copy of the Bolero Book can be found here: http://camshaft.github.io/bolero

## Quick Start

1. Install subcommand and add a dependency

    ```console
    $ cargo add --dev bolero
    $ cargo install -f cargo-bolero
    ```

2. Write a test using [`bolero::check!`](https://docs.rs/bolero/latest/bolero/macro.check.html) macro:

    ```rust
    pub fn buggy_add(x: u32, y: u32) -> u32 {
        if x == 12976 && y == 14867 {
            return x.wrapping_sub(y);
        }
        return x.wrapping_add(y);
    }

    #[test]
    fn fuzz_add() {
        bolero::check!()
            .with_type()
            .cloned()
            .for_each(|(a, b)| buggy_add(a, b) == a.wrapping_add(b));
    }
    ```

3. Run the test with `cargo bolero`

    ```console
    $ cargo bolero test fuzz_add

    # ... some moments later ...

    ======================== Test Failure ========================

    Input:
    (
        12976,
        14867,
    )

    Error:
    test returned `false`

    ==============================================================
    ```

### Linux Installation

`cargo-bolero` needs a couple of libraries installed to compile. If these libraries aren't
available the requirement can be relaxed by executing `cargo install cargo-bolero --no-default-features -f`

#### Debian/Ubuntu

```bash
$ sudo apt install binutils-dev libunwind-dev
```

### Verbose Output

Set `BOLERO_VERBOSE` to enable additional output during test runs:

```console
$ BOLERO_VERBOSE=seed cargo test
running tests::model_test with seed=257980385844766853829307593552934182957
running tests::model_test with seed=89281095907698073451614483067208970550
```

Accepted values (comma-separated):
- `seed` — print the seed before each RNG-based iteration
- `1` or `all` — enable all verbose output

This can also be enabled per-test in code:

```rust
use bolero::{check, Verbose};

check!()
    .with_verbose(Verbose::Seed)
    .for_each(|input| {
        // ...
    });
```
