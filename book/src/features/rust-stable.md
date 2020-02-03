# Works on Rust Stable

`bolero` does not require nightly to execute fuzz targets in the case a sanitizer has not been specified.

```bash
# does not require nightly
$ cargo bolero fuzz my_fuzz_target

# requires nightly
$ cargo bolero fuzz --sanitizer address my_fuzz_target
```
