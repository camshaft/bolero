use crate::Seed;

/// The engine kind currently running the test
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EngineKind {
    /// The default test engine (used when running `cargo test`)
    Test,
    /// The libfuzzer engine
    LibFuzzer,
    /// The AFL engine
    Afl,
    /// The Honggfuzz engine
    Honggfuzz,
    /// The Kani model-checking engine
    Kani,
}

/// The phase of the current test run
#[derive(Clone, Debug, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum RunPhase {
    /// A normal test iteration — the harness is generating and testing inputs
    #[default]
    Normal,
    /// A shrinking iteration — the harness is trying to minimize a failing input
    Shrink,
    /// A failure has been confirmed and is about to be reported
    Failure,
}

/// Information about the current test input
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct TestInput {
    /// The RNG seed used to generate the input, if applicable (set by the `Test` engine)
    pub seed: Option<Seed>,
    /// The file path of the corpus/crash input being tested, if applicable (set by the `Test`
    /// engine)
    pub file: Option<std::path::PathBuf>,
}

impl TestInput {
    #[doc(hidden)]
    pub fn new(seed: Option<Seed>, file: Option<std::path::PathBuf>) -> Self {
        Self { seed, file }
    }
}

/// Context about the current test run, available inside a running bolero test harness
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct TestRunContext {
    /// The engine kind being used
    pub engine: EngineKind,
    /// Information about the current test input
    pub input: TestInput,
    /// The number of test iterations executed so far in this harness run.
    ///
    /// This can be used by logging/tracing filters to suppress output during the
    /// bulk of test iterations and only emit diagnostics on a specific iteration
    /// (e.g., the final replay after shrinking).
    pub iteration: u64,
    /// The current phase of the test run.
    ///
    /// Logging/tracing filters can use this to emit diagnostics only during
    /// specific phases, for example suppressing output during [`RunPhase::Normal`]
    /// and enabling it during [`RunPhase::Shrink`] or [`RunPhase::Failure`].
    pub run_phase: RunPhase,
}

impl TestRunContext {
    #[doc(hidden)]
    pub fn new(engine: EngineKind, input: TestInput, iteration: u64, run_phase: RunPhase) -> Self {
        Self {
            engine,
            input,
            iteration,
            run_phase,
        }
    }
}

#[cfg(kani)]
mod kani_impl {
    use super::{EngineKind, RunPhase, TestInput, TestRunContext};

    /// Returns `true` if the current code is executing inside a bolero test harness
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// fn my_function(input: &[u8]) {
    ///     if bolero::is_active() {
    ///         // modify behavior during fuzzing/property testing
    ///     }
    /// }
    /// ```
    pub fn is_active() -> bool {
        true
    }

    /// Returns the current [`TestRunContext`] if executing inside a bolero test harness,
    /// or `None` otherwise
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// fn my_function(input: &[u8]) {
    ///     if let Some(ctx) = bolero::current_context() {
    ///         eprintln!("engine: {:?}, seed: {:?}", ctx.engine, ctx.input.seed);
    ///     }
    /// }
    /// ```
    pub fn current_context() -> Option<TestRunContext> {
        Some(TestRunContext::new(
            EngineKind::Kani,
            TestInput::default(),
            0,
            RunPhase::Normal,
        ))
    }
}

#[cfg(not(kani))]
mod std_impl {
    use super::{RunPhase, TestInput, TestRunContext};
    use core::cell::RefCell;

    thread_local! {
        static CONTEXT: RefCell<Option<TestRunContext>> = const { RefCell::new(None) };
    }

    /// Returns `true` if the current code is executing inside a bolero test harness
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// fn my_function(input: &[u8]) {
    ///     if bolero::is_active() {
    ///         // modify behavior during fuzzing/property testing
    ///     }
    /// }
    /// ```
    pub fn is_active() -> bool {
        CONTEXT.with(|ctx| ctx.borrow().is_some())
    }

    /// Returns the current [`TestRunContext`] if executing inside a bolero test harness,
    /// or `None` otherwise
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// fn my_function(input: &[u8]) {
    ///     if let Some(ctx) = bolero::current_context() {
    ///         eprintln!("engine: {:?}, seed: {:?}", ctx.engine, ctx.input.seed);
    ///     }
    /// }
    /// ```
    pub fn current_context() -> Option<TestRunContext> {
        CONTEXT.with(|ctx| ctx.borrow().clone())
    }

    /// Updates the `iteration` field of the current test context in-place.
    ///
    /// Has no effect when called outside a bolero test harness.
    #[doc(hidden)]
    pub fn set_iteration(iteration: u64) {
        CONTEXT.with(|ctx| {
            if let Some(c) = ctx.borrow_mut().as_mut() {
                c.iteration = iteration;
            }
        });
    }

    /// Updates the `run_phase` field of the current test context in-place.
    ///
    /// Has no effect when called outside a bolero test harness.
    #[doc(hidden)]
    pub fn set_run_phase(run_phase: RunPhase) {
        CONTEXT.with(|ctx| {
            if let Some(c) = ctx.borrow_mut().as_mut() {
                c.run_phase = run_phase;
            }
        });
    }

    /// Updates the `input` field of the current test context in-place.
    ///
    /// Has no effect when called outside a bolero test harness.
    #[doc(hidden)]
    pub fn set_input(input: TestInput) {
        CONTEXT.with(|ctx| {
            if let Some(c) = ctx.borrow_mut().as_mut() {
                c.input = input;
            }
        });
    }

    /// A guard that restores the previous test context when dropped.
    ///
    /// Obtained by calling [`enter`].
    #[doc(hidden)]
    pub struct ContextGuard {
        prev: Option<TestRunContext>,
    }

    impl Drop for ContextGuard {
        fn drop(&mut self) {
            CONTEXT.with(|ctx| *ctx.borrow_mut() = self.prev.take());
        }
    }

    /// Enter a test context, returning a [`ContextGuard`] that restores the previous context on drop.
    #[doc(hidden)]
    pub fn enter(context: TestRunContext) -> ContextGuard {
        let prev = CONTEXT.with(|ctx| ctx.borrow_mut().replace(context));
        ContextGuard { prev }
    }
}

#[cfg(kani)]
pub use kani_impl::{current_context, is_active};

#[cfg(not(kani))]
pub use std_impl::{
    current_context, enter, is_active, set_input, set_iteration, set_run_phase, ContextGuard,
};
