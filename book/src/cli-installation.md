# CLI Installation

`bolero` provides a CLI program to execute tests, [`cargo-bolero`](https://crates.io/crates/cargo-bolero). It can be installed globally with cargo:

```bash
$ cargo install cargo-bolero -f
```

## Linux Installation

`cargo-bolero` needs a couple of libraries installed to compile. If these libraries aren't
available the requirement can be relaxed by executing `cargo install cargo-bolero --no-default-features -f`

### Debian/Ubuntu

```bash
$ sudo apt install binutils-dev libunwind-dev
```

### Nix

```bash
$ nix-shell -p libbfd libunwind libopcodes
```
