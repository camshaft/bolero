use crate::Seed;
#[cfg(not(kani))]
use core::cell::RefCell;

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
}

impl TestRunContext {
    #[doc(hidden)]
    pub fn new(engine: EngineKind, input: TestInput) -> Self {
        Self { engine, input }
    }
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
#[cfg(kani)]
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
#[cfg(kani)]
pub fn current_context() -> Option<TestRunContext> {
    Some(TestRunContext::new(EngineKind::Kani, TestInput::default()))
}

#[cfg(not(kani))]
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
#[cfg(not(kani))]
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
#[cfg(not(kani))]
pub fn current_context() -> Option<TestRunContext> {
    CONTEXT.with(|ctx| ctx.borrow().clone())
}

/// A guard that restores the previous test context when dropped.
///
/// Obtained by calling [`enter`].
#[doc(hidden)]
#[cfg(not(kani))]
pub struct ContextGuard {
    prev: Option<TestRunContext>,
}

#[cfg(not(kani))]
impl Drop for ContextGuard {
    fn drop(&mut self) {
        CONTEXT.with(|ctx| *ctx.borrow_mut() = self.prev.take());
    }
}

/// Enter a test context, returning a [`ContextGuard`] that restores the previous context on drop.
#[doc(hidden)]
#[cfg(not(kani))]
pub fn enter(context: TestRunContext) -> ContextGuard {
    let prev = CONTEXT.with(|ctx| ctx.borrow_mut().replace(context));
    ContextGuard { prev }
}
