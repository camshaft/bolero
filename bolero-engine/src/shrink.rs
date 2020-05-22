use crate::{panic, panic::PanicError, Test, TestFailure, TestInput};
use bolero_generator::driver::{ByteSliceDriver, DriverMode};

/// Shrink the input to a simpler form
pub fn shrink<T: Test>(
    test: &mut T,
    input: Vec<u8>,
    seed: Option<u64>,
    driver_mode: Option<DriverMode>,
) -> Option<TestFailure<T::Value>> {
    Shrinker::new(test, input, seed, driver_mode).shrink()
}

macro_rules! ensure {
    ($expr:expr) => {
        if !($expr) {
            return Err(());
        }
    };
}

macro_rules! shrink_integer {
    ($current:ident, $check:expr) => {{
        let mut check = $check;

        let mut lowest_panic = None;
        let mut prev_value = $current;

        while prev_value > 0 {
            let next_value = prev_value / 2;
            if check(next_value) {
                lowest_panic = Some(next_value);
                prev_value = next_value;
            } else {
                break;
            }
        }

        while let Some(next_value) = prev_value.checked_sub(1) {
            if check(next_value) {
                lowest_panic = Some(next_value);
            }
            prev_value = next_value;
        }

        lowest_panic
    }};
}

#[derive(Debug)]
struct Shrinker<'a, T> {
    test: &'a mut T,
    input: Vec<u8>,
    len: usize,
    seed: Option<u64>,
    driver_mode: Option<DriverMode>,
}

impl<'a, T: Test> Shrinker<'a, T> {
    fn new(
        test: &'a mut T,
        input: Vec<u8>,
        seed: Option<u64>,
        driver_mode: Option<DriverMode>,
    ) -> Self {
        let len = input.len();
        Self {
            input,
            len,
            test,
            seed,
            driver_mode,
        }
    }

    fn shrink(mut self) -> Option<TestFailure<T::Value>> {
        panic::set_hook();
        let forward_panic = panic::forward_panic(false);
        let capture_backtrace = panic::capture_backtrace(false);

        // Skip inputs that don't panic
        if self.execute().is_ok() {
            panic::forward_panic(forward_panic);
            panic::capture_backtrace(capture_backtrace);
            return None;
        }

        let mut was_changed;
        // put a limit on the number of shrink iterations
        for _ in 0..1000 {
            was_changed = self.apply_truncation().is_ok();

            for index in 0..self.len {
                if index >= self.len {
                    // the length changed so start a new loop
                    break;
                }

                was_changed |= self.apply_transforms(index);
            }

            if !was_changed {
                break;
            }
        }

        panic::capture_backtrace(capture_backtrace);
        let error = self.execute().err().unwrap();
        panic::capture_backtrace(false);

        let input = self.generate_value();

        panic::forward_panic(forward_panic);
        panic::capture_backtrace(capture_backtrace);

        Some(TestFailure {
            seed: self.seed,
            error,
            input,
        })
    }

    fn apply_transforms(&mut self, index: usize) -> bool {
        let mut is_valid_transform = false;
        is_valid_transform |= self.apply_lower_byte(index).is_ok();
        is_valid_transform |= self.apply_sort(index).is_ok();
        is_valid_transform |= self.apply_remove_chunk(index).is_ok();
        is_valid_transform
    }

    fn apply_lower_byte(&mut self, index: usize) -> Result<(), ()> {
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

    fn apply_truncation(&mut self) -> Result<(), ()> {
        let prev_value = self.input.len();
        let result = shrink_integer!(prev_value, |value| {
            self.len = value;
            self.execute().is_err()
        });

        if let Some(len) = result {
            self.len = len;
            self.input.truncate(len);
            Ok(())
        } else {
            // revert
            self.len = prev_value;
            Err(())
        }
    }

    fn apply_remove_chunk(&mut self, index: usize) -> Result<(), ()> {
        let prev = self.input[index..].to_vec();
        let mut lowest_panic = None;

        for (offset, _) in prev.iter().enumerate() {
            self.input.remove(index);
            self.len -= 1;
            if self.execute().is_err() {
                lowest_panic = Some(offset);
            }
        }

        self.input.truncate(index);
        let res = if let Some(offset) = lowest_panic {
            self.input.extend_from_slice(&prev[offset..]);
            Ok(())
        } else {
            self.input.extend_from_slice(&prev[..]);
            Err(())
        };
        self.len = self.input.len();

        res
    }

    fn apply_sort(&mut self, index: usize) -> Result<(), ()> {
        ensure!(index + 1 < self.input.len());
        ensure!(self.input[index] > self.input[index + 1]);

        let first = self.input[index];
        let second = self.input[index + 1];
        self.input[index] = second;
        self.input[index + 1] = first;

        if self.execute().is_err() {
            return Ok(());
        }

        // revert
        self.input[index] = first;
        self.input[index + 1] = second;
        Err(())
    }

    fn execute(&mut self) -> Result<bool, PanicError> {
        self.test.test(&mut ShrinkInput {
            input: &self.input[..self.len],
            driver_mode: self.driver_mode,
        })
    }

    fn generate_value(&mut self) -> T::Value {
        self.test.generate_value(&mut ShrinkInput {
            input: &self.input[..self.len],
            driver_mode: self.driver_mode,
        })
    }
}

struct ShrinkInput<'a> {
    input: &'a [u8],
    driver_mode: Option<DriverMode>,
}

impl<'a, Output> TestInput<Output> for ShrinkInput<'a> {
    type Driver = ByteSliceDriver<'a>;

    fn with_slice<F: FnMut(&[u8]) -> Output>(&mut self, f: &mut F) -> Output {
        f(self.input)
    }

    fn with_driver<F: FnMut(&mut Self::Driver) -> Output>(&mut self, f: &mut F) -> Output {
        f(&mut ByteSliceDriver::new(self.input, self.driver_mode))
    }
}

macro_rules! shrink_test {
    ($name:ident, $gen:expr, $expected:expr, $check:expr) => {
        #[test]
        fn $name() {
            #[allow(unused_imports)]
            use bolero_generator::{driver::DriverMode, gen, ValueGenerator};

            let mut test = crate::ClonedGeneratorTest::new($check, $gen);
            let input = [255; 1024].to_vec();

            let failure = Shrinker::new(&mut test, input, None, Some(DriverMode::Forced))
                .shrink()
                .unwrap();

            assert_eq!(failure.input, $expected);
        }
    };
}

shrink_test!(u16_shrink_test, gen::<u16>(), 1, |value| {
    assert!(value < 20);
    assert!(value % 7 == 0);
});

shrink_test!(u32_shrink_test, gen::<u32>(), 20, |value| {
    assert!(value < 20);
});

shrink_test!(
    vec_shrink_test,
    gen::<Vec<u32>>().filter(|vec| vec.len() >= 3),
    vec![4, 0, 0],
    |value: Vec<u32>| {
        assert!(value[0] < 4);
        assert!(value[1] < 5);
        assert!(value[2] < 6);
    }
);

shrink_test!(
    non_start_vec_shrink_test,
    gen::<Vec<u32>>().filter(|vec| vec.len() >= 3),
    vec![0, 5, 0],
    |value: Vec<u32>| {
        assert!(value[1] < 5);
        assert!(value[2] < 6);
    }
);
