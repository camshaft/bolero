pub const BUILD_FLAGS: &[&str] = &[
    "--cfg fuzzing_ravel",
    "-Cllvm-args=-sanitizer-coverage-inline-8bit-counters",
    "-Cllvm-args=-sanitizer-coverage-level=4",
    "-Cllvm-args=-sanitizer-coverage-pc-table",
    "-Cllvm-args=-sanitizer-coverage-prune-blocks=0",
    "-Cllvm-args=-sanitizer-coverage-trace-compares",
    "-Cllvm-args=-sanitizer-coverage-trace-divs",
    "-Cllvm-args=-sanitizer-coverage-trace-geps",
    #[cfg(target_os = "linux")]
    "-Cllvm-args=-sanitizer-coverage-stack-depth",
];

mod fuzz;
mod process;
mod reduce;
pub mod test_target;

pub use fuzz::*;
pub use reduce::*;
pub use test_target::*;
