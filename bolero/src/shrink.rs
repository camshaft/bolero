// WIP

use std::panic::{catch_unwind, AssertUnwindSafe, RefUnwindSafe};

#[derive(Debug)]
pub struct Shrinker<F> {
    input: Vec<u8>,
    len: usize,
    testfn: F,
}

macro_rules! ensure {
    ($expr:expr) => {
        if !($expr) {
            return Err(());
        }
    };
}

macro_rules! ensure_panics {
    ($self:ident) => {
        if $self.execute().is_err() {
            return Ok(());
        }
    };
}

macro_rules! shrink_integer {
    ($current:ident, $check:expr) => {{
        // TODO implement an efficient binary search

        // let mut check = $check;
        // let mut size = $current;
        // if size == 0 {
        //     None
        // } else {
        //     let mut base = None;
        //     while size > 1 {
        //         let half = size / 2;
        //         let mid = base.unwrap_or(0) + half;
        //         if check(mid) {
        //             base = Some(mid);
        //         };
        //         size -= half;
        //     }
        //     base
        // }

        let mut check = $check;

        let mut lowest_panic = None;
        let mut prev_value = $current;
        while let Some(next_value) = prev_value.checked_sub(1) {
            if check(next_value) {
                lowest_panic = Some(next_value);
            }
            prev_value = next_value;
        }
        lowest_panic
    }};
}

impl<F: RefUnwindSafe + FnMut(&[u8]) -> bool> Shrinker<F> {
    pub fn new(input: &[u8], testfn: F) -> Self {
        Self {
            input: input.to_vec(),
            len: input.len(),
            testfn,
        }
    }

    pub fn shrink(mut self) -> Vec<u8> {
        // Skip inputs that don't panic
        if self.execute().is_ok() {
            return self.input;
        }

        #[cfg(not(test))]
        let panic_hook = std::panic::take_hook();

        #[cfg(not(test))]
        std::panic::set_hook(Box::new(|_| {
            // noop
        }));

        let mut was_changed = true;
        while was_changed {
            was_changed = self.apply_truncation().is_ok();

            for index in 0..self.len {
                if index >= self.len {
                    // the length changed so start a new loop
                    break;
                }

                was_changed |= self.apply_transforms(index);
            }
        }

        #[cfg(not(test))]
        std::panic::set_hook(panic_hook);

        self.input.truncate(self.len);
        self.input
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
        ensure_panics!(self);

        // revert
        self.input[index] = first;
        self.input[index + 1] = second;
        Err(())
    }

    fn execute(&mut self) -> Result<bool, ()> {
        catch_unwind(AssertUnwindSafe(|| (self.testfn)(&self.input[..self.len]))).map_err(|_| ())
    }
}

macro_rules! shrink_test {
    ($name:ident, $gen:expr, $expected:expr, $check:expr) => {
        #[test]
        fn $name() {
            use crate::generator::{gen, rng::FuzzRng, ValueGenerator};

            let generator = $gen;
            let to_value = |input: &[u8]| {
                let mut rng = FuzzRng::new(input);
                generator.generate(&mut rng)
            };

            let check = $check;

            let output = Shrinker::new(&[255; 1024][..], |input| {
                if let Some(value) = to_value(input) {
                    check(value);
                    true
                } else {
                    false
                }
            })
            .shrink();

            assert_eq!(to_value(&output).unwrap(), $expected);
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
