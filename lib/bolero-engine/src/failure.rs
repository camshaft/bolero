use crate::{
    panic::{rust_backtrace, PanicError},
    Seed,
};
use core::fmt::{Debug, Display};

#[derive(Debug, Default)]
#[non_exhaustive]
pub enum ExitStrategy {
    #[default]
    Panic,
    Abort,
    Exit,
}

impl ExitStrategy {
    fn exit(&self) {
        match self {
            ExitStrategy::Panic => panic!("test failed"),
            ExitStrategy::Abort => std::process::abort(),
            ExitStrategy::Exit => std::process::exit(1),
        }
    }
}

/// Contains information about a test failure
#[derive(Debug)]
#[non_exhaustive]
pub struct Failure<Input> {
    pub error: PanicError,
    pub input: Input,
    pub seed: Option<Seed>,
    pub exit_strategy: ExitStrategy,
}

impl<Input: Debug> Failure<Input> {
    pub fn new(input: Input, error: PanicError) -> Self {
        Self {
            input,
            error,
            seed: None,
            exit_strategy: Default::default(),
        }
    }

    pub fn with_seed(mut self, seed: Option<Seed>) -> Self {
        self.seed = seed;
        self
    }

    pub fn exit(self) {
        eprintln!("{self:#}");
        self.exit_strategy.exit()
    }
}

impl<Input: Debug> Display for Failure<Input> {
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
            if let Some(backtrace) = self.error.backtrace.as_ref().filter(|_| rust_backtrace()) {
                writeln!(f, "{}", backtrace)?;
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

impl<Input: Debug> std::error::Error for Failure<Input> {}
