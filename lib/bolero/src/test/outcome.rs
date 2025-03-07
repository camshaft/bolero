use bolero_engine::TargetLocation;
use core::{fmt, time::Duration};
use std::time::Instant;

pub enum ExitReason {
    MaxDurationExceeded { limit: Duration, default: bool },
    TestFailure,
}

impl fmt::Display for ExitReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExitReason::MaxDurationExceeded { limit, default } => {
                write!(
                    f,
                    "max duration ({:?}{}) exceeded",
                    limit,
                    if *default { " - default" } else { "" }
                )
            }
            ExitReason::TestFailure => write!(f, "test failure"),
        }
    }
}

pub struct Outcome<'a> {
    location: &'a TargetLocation,
    start_time: Instant,
    corpus_input: u64,
    rng_input: u64,
    exhaustive_input: u64,
    total: u64,
    exit_reason: Option<ExitReason>,
}

impl fmt::Display for Outcome<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let runtime = self.start_time.elapsed();

        if let Some(name) = self.location.test_name.as_ref() {
            write!(f, "test {name} ...\t")?;
        } else {
            write!(f, "test {} ...\t", self.location.item_path())?;
        }

        write!(f, "run time: {runtime:?} | ")?;

        let mut ips = self.total as f64 / runtime.as_secs_f64();
        if ips > 10.0 {
            ips = ips.round();
            write!(f, "iterations/s: {ips}")?;
        } else {
            write!(f, "iterations/s: {ips:0.2}")?;
        }

        for (label, count) in [
            ("corpus inputs", self.corpus_input),
            ("rng inputs", self.rng_input),
            ("exhaustive inputs", self.exhaustive_input),
        ] {
            if count > 0 {
                write!(f, " | {label}: {count}")?;
            }
        }

        if let Some(reason) = &self.exit_reason {
            write!(f, " | exit reason: {}", reason)?;
        }

        Ok(())
    }
}

impl<'a> Outcome<'a> {
    pub fn new(location: &'a TargetLocation, start_time: Instant) -> Self {
        Self {
            location,
            start_time,
            corpus_input: 0,
            rng_input: 0,
            exhaustive_input: 0,
            total: 0,
            exit_reason: None,
        }
    }

    pub fn on_named_test(&mut self, test: &super::input::Test) {
        match test {
            super::input::Test::Rng(_) => self.on_rng_input(),
            super::input::Test::File(_) => self.on_corpus_input(),
        }
    }

    pub fn on_corpus_input(&mut self) {
        progress();
        self.corpus_input += 1;
        self.total += 1;
    }

    pub fn on_rng_input(&mut self) {
        progress();
        self.rng_input += 1;
        self.total += 1;
    }

    pub fn on_exhaustive_input(&mut self) {
        self.exhaustive_input += 1;
        self.total += 1;
    }

    pub fn on_exit(&mut self, reason: ExitReason) {
        self.exit_reason = Some(reason);
    }
}

impl Drop for Outcome<'_> {
    fn drop(&mut self) {
        eprintln!("{}", self.to_string());
    }
}

fn progress() {
    if cfg!(miri) {
        use std::io::{stderr, Write};

        // miri doesn't capture explicit writes to stderr
        #[allow(clippy::explicit_write)]
        let _ = write!(stderr(), ".");
    }
}
