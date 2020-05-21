use anyhow::Error;
use core::fmt::{Debug, Display};

/// Contains information about a test failure
#[derive(Debug)]
pub struct TestFailure<Input> {
    pub error: Error,
    pub input: Input,
    pub seed: Option<u64>,
}

impl<Input: Debug> Display for TestFailure<Input> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        writeln!(
            f,
            "\n======================== Test Failure ========================\n"
        )?;
        if let Some(seed) = &self.seed {
            writeln!(f, "BOLERO_RANDOM_SEED={}\n", seed)?;
        }
        writeln!(f, "Input: \n{:#?}\n", self.input)?;
        writeln!(f, "Error: \n{}", self.error)?;

        if f.alternate() {
            if std::env::var("RUST_BACKTRACE")
                .ok()
                .filter(|v| v == "1")
                .is_some()
            {
                writeln!(f, "{}", self.error.backtrace())?;
            } else {
                writeln!(f, "note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace.")?;
            }
        }

        writeln!(
            f,
            "\n=============================================================="
        )?;
        Ok(())
    }
}

impl<Input: Debug> std::error::Error for TestFailure<Input> {}
