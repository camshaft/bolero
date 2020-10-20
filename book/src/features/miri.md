# Miri Support

`bolero` supports executing tests with [Miri](https://github.com/rust-lang/miri). Keep in mind that execution is significantly slower in Miri.

The isolation mode must currently be disabled in order for bolero tests to read corpuses from the file system. This can be done by setting the appropriate flags:

```bash
MIRIFLAGS="-Zmiri-disable-isolation" cargo +nightly miri test
```
