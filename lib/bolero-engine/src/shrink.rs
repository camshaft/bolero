use crate::{panic, panic::PanicError, Test, TestFailure, TestInput};
use bolero_generator::driver::{self, ByteSliceDriver};
use std::time::Instant;

#[cfg(test)]
mod tests;

/// Shrink the input to a simpler form
pub fn shrink<T: Test>(
    test: &mut T,
    input: Vec<u8>,
    seed: Option<u64>,
    options: &driver::Options,
) -> Option<TestFailure<T::Value>> {
    Shrinker::new(test, input, seed, options).shrink()
}

macro_rules! predicate {
    ($expr:expr) => {
        if !($expr) {
            return Err(());
        }
    };
}

macro_rules! shrink_integer {
    ($current:expr, $check:expr) => {{
        let mut check = $check;

        (0..($current)).into_iter().find(|value| check(*value))
    }};
}

#[derive(Debug)]
struct Shrinker<'a, T> {
    test: &'a mut T,
    input: Vec<u8>,
    temp_input: Vec<u8>,
    end: usize,
    seed: Option<u64>,
    options: &'a driver::Options,
    #[cfg(test)]
    snapshot_input: Vec<u8>,
}

impl<'a, T: Test> Shrinker<'a, T> {
    fn new(
        test: &'a mut T,
        input: Vec<u8>,
        seed: Option<u64>,
        options: &'a driver::Options,
    ) -> Self {
        let len = input.len();
        Self {
            temp_input: input.clone(),
            input,
            end: len,
            test,
            seed,
            options,
            #[cfg(test)]
            snapshot_input: vec![],
        }
    }

    fn shrink(mut self) -> Option<TestFailure<T::Value>> {
        panic::set_hook();
        let forward_panic = panic::forward_panic(false);
        let capture_backtrace = panic::capture_backtrace(false);

        if cfg!(test) {
            panic::forward_panic(forward_panic);
            assert!(
                self.execute().is_err(),
                "shrinking should only be performed on a failing test"
            );
            panic::forward_panic(false);
        }

        let mut was_changed;
        let start_time = Instant::now();
        let shrink_time = self.options.shrink_time_or_default();

        loop {
            was_changed = self.apply_truncation();

            // empty input means we're done
            if self.end == 0 {
                break;
            }

            for index in 0..self.end {
                if index >= self.end {
                    // the length changed so start a new loop
                    break;
                }

                self.apply_transforms(index, &mut was_changed);
            }

            // we made it through all of the transforms without shrinking
            // which means it's as small as it's going to get
            if !was_changed {
                break;
            }

            // put a time limit on the number of shrink iterations
            if start_time.elapsed() > shrink_time {
                break;
            }
        }

        panic::capture_backtrace(capture_backtrace);
        let error = self.execute().err()?;
        panic::capture_backtrace(false);

        let input = self.generate_value();

        // restore settings
        panic::forward_panic(forward_panic);
        panic::capture_backtrace(capture_backtrace);

        Some(TestFailure {
            seed: self.seed,
            error,
            input,
        })
    }

    fn apply_truncation(&mut self) -> bool {
        self.apply("truncation end", |this| this.apply_truncation_end())
    }

    fn apply_truncation_end(&mut self) -> Result<(), ()> {
        let prev_value = self.end;
        let result = shrink_integer!(prev_value, |end| {
            self.end = end;
            self.execute().is_err()
        });

        if let Some(end) = result {
            self.end = end;
            Ok(())
        } else {
            // revert
            self.end = prev_value;
            Err(())
        }
    }

    fn apply_transforms(&mut self, index: usize, was_changed: &mut bool) {
        *was_changed |= self.apply("remove chunk", |this| this.apply_remove_chunk(index));

        // try the more aggressive transforms before moving to the single-byte transforms
        if *was_changed {
            return;
        }

        *was_changed |= self.apply("sort", |this| this.apply_sort(index));

        *was_changed |= self.apply("byte shrink", |this| this.apply_byte_shrink(index));
    }

    fn apply_byte_shrink(&mut self, index: usize) -> Result<(), ()> {
        let prev_value = self.input[index];
        let result = shrink_integer!(prev_value, |value| {
            self.input[index] = value;
            self.execute().is_err()
        });

        if let Some(value) = result {
            self.input[index] = value;
            Ok(())
        } else {
            // revert
            self.input[index] = prev_value;
            Err(())
        }
    }

    fn apply_remove_chunk(&mut self, index: usize) -> Result<(), ()> {
        // since most generators are going to use at least the first byte we don't remove it
        predicate!(index != 0);

        let slice = &self.input[index..self.end];

        // we need at least one byte to remove and one to shift up in its place
        predicate!(slice.len() >= 2);

        // store the previous input
        let mut temp_input = core::mem::take(&mut self.temp_input);
        temp_input.clear();
        temp_input.extend_from_slice(slice);

        // we need at least one byte to shift up
        let max_len = temp_input.len() - 1;

        let result = shrink_integer!(max_len, |diff| {
            self.input.truncate(index);
            let offset = max_len - diff;
            let slice = &temp_input[offset..];

            // ensure the slicing logic makes sense
            if cfg!(test) {
                // the slice should be at least 1 and equal to diff + 1
                assert_eq!(slice.len(), diff + 1);
            }

            self.input.extend_from_slice(slice);
            self.end = self.input.len();
            self.execute().is_err()
        });

        self.input.truncate(index);

        let res = if let Some(diff) = result {
            let offset = max_len - diff;
            self.input.extend_from_slice(&temp_input[offset..]);
            Ok(())
        } else {
            self.input.extend_from_slice(&temp_input);
            Err(())
        };

        self.temp_input = temp_input;
        self.end = self.input.len();

        res
    }

    fn apply_sort(&mut self, index: usize) -> Result<(), ()> {
        // make sure we have at least 1 byte to swap with
        predicate!(index + 1 < self.end);
        predicate!(self.input[index] > self.input[index + 1]);

        self.input.swap(index, index + 1);

        if self.execute().is_err() {
            return Ok(());
        }

        // revert
        self.input.swap(index, index + 1);

        Err(())
    }

    #[inline(always)]
    fn apply<F: FnOnce(&mut Self) -> Result<(), ()>>(&mut self, transform: &str, f: F) -> bool {
        // store a snapshot of the previous input
        #[cfg(test)]
        {
            self.snapshot_input.truncate(0);
            self.snapshot_input
                .extend_from_slice(&self.input[..self.end]);
        }

        let result = f(self).is_ok();

        // ensures that the test is failing under the current input
        //
        // if not, this would indicate a invalid transform or non-determinsitic test
        #[cfg(test)]
        {
            if self.execute().is_ok() {
                eprintln!(
                    "transform created non-failing test: {}\nBEFORE: {:?}\nAFTER: {:?}",
                    transform,
                    &self.snapshot_input,
                    &self.input[..self.end],
                );
                panic!();
            }
        }

        let _ = transform;

        result
    }

    fn execute(&mut self) -> Result<bool, PanicError> {
        self.test.test(&mut ShrinkInput {
            input: &self.input[..self.end],
            options: self.options,
        })
    }

    fn generate_value(&mut self) -> T::Value {
        self.test.generate_value(&mut ShrinkInput {
            input: &self.input[..self.end],
            options: self.options,
        })
    }
}

struct ShrinkInput<'a> {
    input: &'a [u8],
    options: &'a driver::Options,
}

impl<'a, Output> TestInput<Output> for ShrinkInput<'a> {
    type Driver = ByteSliceDriver<'a>;

    fn with_slice<F: FnMut(&[u8]) -> Output>(&mut self, f: &mut F) -> Output {
        f(self.input)
    }

    fn with_driver<F: FnMut(&mut Self::Driver) -> Output>(&mut self, f: &mut F) -> Output {
        f(&mut ByteSliceDriver::new(self.input, self.options))
    }
}
