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
    /// Whether the harness will attempt to shrink failing inputs.
    ///
    /// When `false`, the harness transitions directly from [`RunPhase::Normal`] to
    /// [`RunPhase::Failure`] on the first detected failure without any
    /// [`RunPhase::Shrink`] iterations in between.  Applications that buffer
    /// diagnostic output and emit it only on [`RunPhase::Failure`] do not need to
    /// change their strategy — a [`RunPhase::Failure`] re-run always occurs
    /// regardless of this flag — but they can use it to decide, for example,
    /// whether to capture a full trace or just a lightweight summary.
    pub shrink_enabled: bool,
}

impl TestRunContext {
    #[doc(hidden)]
    pub fn new(engine: EngineKind, input: TestInput, iteration: u64, run_phase: RunPhase) -> Self {
        Self {
            engine,
            input,
            iteration,
            run_phase,
            shrink_enabled: true,
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

    /// Calls `f` with a reference to the current [`TestRunContext`] and returns the result,
    /// or returns `None` if not inside a bolero test harness.
    ///
    /// This is cheaper than [`current_context`] because it avoids cloning the context.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// fn my_function(input: &[u8]) {
    ///     bolero::with_context(|ctx| {
    ///         eprintln!("phase: {:?}", ctx.run_phase);
    ///     });
    /// }
    /// ```
    pub fn with_context<F, R>(f: F) -> Option<R>
    where
        F: FnOnce(&TestRunContext) -> R,
    {
        let ctx = TestRunContext::new(EngineKind::Kani, TestInput::default(), 0, RunPhase::Normal);
        Some(f(&ctx))
    }

    /// No-op in kani — context state is not tracked.
    #[doc(hidden)]
    pub fn update<F: FnOnce(&mut TestRunContext)>(_f: F) {}

    /// Register a callback to be invoked right before the test failure is reported.
    ///
    /// No-op in kani — the model checker does not support this mechanism.
    pub fn on_failure(_f: impl FnOnce() + 'static) {}

    /// No-op in kani.
    #[doc(hidden)]
    pub fn invoke_on_failure() {}

    /// No-op in kani.
    #[doc(hidden)]
    pub fn clear_on_failure() {}
}

#[cfg(not(kani))]
mod std_impl {
    use super::{RunPhase, TestInput, TestRunContext};
    use core::cell::RefCell;

    thread_local! {
        static CONTEXT: RefCell<Option<TestRunContext>> = const { RefCell::new(None) };
        static ON_FAILURE: RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
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

    /// Calls `f` with a reference to the current [`TestRunContext`] and returns the result,
    /// or returns `None` if not inside a bolero test harness.
    ///
    /// This is cheaper than [`current_context`] because it avoids cloning the context.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// fn my_function(input: &[u8]) {
    ///     bolero::with_context(|ctx| {
    ///         eprintln!("phase: {:?}", ctx.run_phase);
    ///     });
    /// }
    /// ```
    pub fn with_context<F, R>(f: F) -> Option<R>
    where
        F: FnOnce(&TestRunContext) -> R,
    {
        CONTEXT.with(|ctx| ctx.borrow().as_ref().map(f))
    }

    /// Mutates the current test context in-place by calling `f`.
    ///
    /// Called by test harnesses to update context fields (iteration counter, run phase,
    /// input) without reconstructing the context guard. A single call can update multiple
    /// fields with only one TLS borrow. Has no effect when called outside a bolero test
    /// harness.
    #[doc(hidden)]
    pub fn update<F>(f: F)
    where
        F: FnOnce(&mut TestRunContext),
    {
        CONTEXT.with(|ctx| {
            if let Some(c) = ctx.borrow_mut().as_mut() {
                f(c);
            }
        });
    }

    /// Register a callback to be invoked right before the test failure is reported.
    ///
    /// The callback is called once, immediately before the harness panics (or aborts in
    /// fuzz engines) to report the confirmed failure. This allows applications to flush
    /// any buffered diagnostic output (e.g., captured tracing spans) in response to the
    /// failure.
    ///
    /// Any previously registered callback for the current iteration is replaced. The
    /// callback is cleared at the start of each test iteration so it must be re-registered
    /// on every call to the test function.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // This example must be `ignore` because it requires running inside a bolero
    /// // test harness (i.e., inside a `check!` target).
    /// fn my_function(input: &[u8]) {
    ///     let log_guard = capture_logs(); // returns buffered log handle
    ///     bolero::on_failure(move || {
    ///         eprintln!("=== captured logs ===\n{}", log_guard.dump());
    ///     });
    ///     // ... test logic ...
    /// }
    /// ```
    pub fn on_failure(f: impl FnOnce() + 'static) {
        ON_FAILURE.with(|cb| *cb.borrow_mut() = Some(Box::new(f)));
    }

    /// Take and invoke the registered `on_failure` callback, if any.
    ///
    /// Called by the harness just before it panics or aborts to report a test failure.
    #[doc(hidden)]
    pub fn invoke_on_failure() {
        let cb = ON_FAILURE.with(|cb| cb.borrow_mut().take());
        if let Some(f) = cb {
            f();
        }
    }

    /// Clear any registered `on_failure` callback.
    ///
    /// Called at the start of each test iteration so that a callback registered during a
    /// previous iteration cannot fire on a subsequent failure.
    #[doc(hidden)]
    pub fn clear_on_failure() {
        ON_FAILURE.with(|cb| *cb.borrow_mut() = None);
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
pub use kani_impl::{
    clear_on_failure, current_context, invoke_on_failure, is_active, on_failure, update,
    with_context,
};

#[cfg(not(kani))]
pub use std_impl::{
    clear_on_failure, current_context, enter, invoke_on_failure, is_active, on_failure, update,
    with_context, ContextGuard,
};
