pub use bolero_generator as generator;
use bolero_generator::RngExt;
use std::{iter::Cycle, path::PathBuf};

mod fuzz;
mod test;

#[cfg(fuzzing)]
pub use fuzz::exec;

#[cfg(not(fuzzing))]
pub use test::exec;

extern "C" {
    #[allow(improper_ctypes)]
    fn __BOLERO__test(input: &[u8]);
}

pub struct CycleRng<I> {
    input: Cycle<I>,
}

impl<I: Clone + Iterator<Item = u8>> CycleRng<I> {
    pub fn new(input: I) -> Self {
        Self {
            input: input.cycle(),
        }
    }
}

impl<I: Clone + Iterator<Item = u8>> generator::RngCore for CycleRng<I> {
    fn next_u32(&mut self) -> u32 {
        self.gen()
    }

    fn next_u64(&mut self) -> u64 {
        self.gen()
    }

    fn fill_bytes(&mut self, bytes: &mut [u8]) {
        for (from, to) in (&mut self.input).zip(bytes.iter_mut()) {
            *to = from;
        }
    }

    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), generator::RngError> {
        self.fill_bytes(bytes);
        Ok(())
    }
}

fn workdir(file: &str) -> String {
    let mut path = PathBuf::from(file);
    path.pop();
    path.to_str().unwrap().to_owned()
}

#[macro_export]
macro_rules! fuzz {
    (for $value:pat in all($gen:expr) { $($tt:tt)* }) => {
        $crate::fuzz!(for $value in ($gen) { $($tt)* });
    };
    (for $value:pat in every($gen:expr) { $($tt:tt)* }) => {
        $crate::fuzz!(for $value in ($gen) { $($tt)* });
    };
    (for $value:pat in ($gen:expr) { $($tt:tt)* }) => {
        $crate::fuzz!(|input| {
            if input.is_empty() {
                return;
            }

            let $value = ($gen).generate(&mut $crate::CycleRng::new(input.iter().copied()));

            $($tt)*
        });
    };
    ($fun:path) => {
        $crate::fuzz!(|input| $fuzz(input););
    };
    (|$input:ident $(: &[u8])?| $impl:expr) => {
        fn main() {
            unsafe { $crate::exec(file!()); }
        }

        #[no_mangle]
        pub extern "C" fn __BOLERO__test($input: &[u8]) {
            $impl
        }
    };
}
