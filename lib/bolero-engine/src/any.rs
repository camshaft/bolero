pub use bolero_generator::any::*;

/// Runs a function that overrides the default driver for `bolero_generator::any` and
/// returns the result
#[cfg(not(kani))]
pub fn run<D, F, R>(driver: Box<D>, test: F) -> (Box<D>, Result<bool, crate::panic::PanicError>)
where
    D: 'static + bolero_generator::driver::object::DynDriver + core::any::Any + Sized,
    F: FnMut() -> R,
    R: super::IntoResult,
{
    let mut test = core::panic::AssertUnwindSafe(test);
    scope::with(driver, || {
        crate::panic::catch(|| test.0().into_result().map(|_| true))
    })
}

/// Runs a function that overrides the default driver for `bolero_generator::any` and
/// returns the result
#[cfg(kani)]
pub fn run<F, R>(
    driver: bolero_generator::kani::Driver,
    mut test: F,
) -> (
    bolero_generator::kani::Driver,
    Result<bool, crate::panic::PanicError>,
)
where
    F: FnMut() -> R,
    R: super::IntoResult,
{
    scope::with(driver, || test().into_result().map(|_| true))
}
