# bolero

[![Build Status](https://github.com/camshaft/bolero/workflows/ci/badge.svg)](https://github.com/camshaft/bolero/actions?workflow=ci)
[![Latest version](https://img.shields.io/crates/v/bolero.svg)](https://crates.io/crates/bolero)
[![Documentation](https://docs.rs/bolero/badge.svg)](https://docs.rs/bolero)
[![License](https://img.shields.io/crates/l/bolero.svg)](https://github.com/camshaft/bolero/blob/master/LICENSE)

fuzz and property testing framework

## Book

A copy of the Bolero Book can be found here: http://camshaft.github.io/bolero

## Installation

`bolero` is on `crates.io` and can be added to a project like so:

```toml
[dev-dependencies]
bolero = "0.4"
```

`bolero` also provides a CLI program to execute fuzz tests, [`cargo-bolero`](https://crates.io/crates/cargo-bolero). It can be installed globally with cargo:

```bash
$ cargo install -f cargo-bolero
```

### Linux Installation

`cargo-bolero` needs a couple of libraries installed to compile. If these libraries aren't
available the requirement can be relaxed by executing `cargo install cargo-bolero --no-default-features -f`

#### Debian/Ubuntu

```bash
$ sudo apt install binutils-dev libunwind-dev
```
