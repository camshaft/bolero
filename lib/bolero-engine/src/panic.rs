use core::{
    cell::RefCell,
    fmt::{Debug, Display},
    panic::PanicInfo,
};
use lazy_static::lazy_static;
use std::{
    panic::{catch_unwind, AssertUnwindSafe, RefUnwindSafe},
    thread_local,
};

macro_rules! backtrace {
    () => {{
        if CAPTURE_BACKTRACE.with(|capture| *capture.borrow()) {
            Some(std::backtrace::Backtrace::capture())
        } else {
            None
        }
    }};
}

thread_local! {
    static ERROR: RefCell<Option<PanicError>> = const { RefCell::new(None) };
    static CAPTURE_BACKTRACE: RefCell<bool> = RefCell::new(*RUST_BACKTRACE);
    static FORWARD_PANIC: RefCell<bool> = const { RefCell::new(true) };
    static THREAD_NAME: String = String::from(std::thread::current().name().unwrap_or("main"));
}

lazy_static! {
    static ref RUST_BACKTRACE: bool = std::env::var("RUST_BACKTRACE")
        .ok()
        .map(|v| v == "1")
        .unwrap_or(false);
    static ref PANIC_HOOK: () = {
        let prev_hook = std::panic::take_hook();

        std::panic::set_hook(Box::new(move |reason| {
            let panic = PanicError {
                message: reason.to_string(),
                location: reason.location().map(|l| l.to_string()),
                backtrace: backtrace!(),
                thread_name: thread_name(),
            };
            ERROR.with(|error| {
                *error.borrow_mut() = Some(panic);
            });
            if FORWARD_PANIC.with(|forward| *forward.borrow()) {
                prev_hook(reason);
            }
        }));
    };
}

#[derive(Debug)]
pub struct PanicError {
    pub(crate) message: String,
    // in some fuzzing modes we don't use these fields so ignore unused warnings
    #[allow(dead_code)]
    pub(crate) location: Option<String>,
    #[allow(dead_code)]
    pub(crate) backtrace: Option<std::backtrace::Backtrace>,
    #[allow(dead_code)]
    pub(crate) thread_name: String,
}

impl std::error::Error for PanicError {}

impl Display for PanicError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl PanicError {
    pub(crate) fn new(message: String) -> Self {
        Self {
            message,
            location: None,
            backtrace: backtrace!(),
            thread_name: thread_name(),
        }
    }
}

#[inline]
pub fn catch<F: RefUnwindSafe + FnOnce() -> Result<bool, PanicError>>(
    fun: F,
) -> Result<bool, PanicError> {
    let res = catch_unwind(AssertUnwindSafe(|| __panic_marker_start__(fun)));
    match res {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(err)) => Err(err),
        Err(err) => {
            if let Some(err) = take_panic() {
                return Err(err);
            }
            macro_rules! try_downcast {
                ($ty:ty, $fmt:expr) => {
                    if let Some(err) = err.downcast_ref::<$ty>() {
                        return Err(PanicError::new(format!($fmt, err)));
                    }
                };
            }

            // if an `any::Error` was returned, then the input wasn't valid
            #[cfg(feature = "any")]
            if err.downcast_ref::<bolero_generator::any::Error>().is_some() {
                return Ok(false);
            }

            try_downcast!(PanicInfo, "{}");
            try_downcast!(anyhow::Error, "{}");
            try_downcast!(String, "{}");
            try_downcast!(&'static str, "{}");
            try_downcast!(Box<dyn Display>, "{}");
            try_downcast!(Box<dyn Debug>, "{:?}");
            Err(PanicError::new(
                "thread panicked with an unknown error".to_string(),
            ))
        }
    }
}

#[inline]
pub fn take_panic() -> Option<PanicError> {
    ERROR.with(|error| error.borrow_mut().take())
}

#[inline]
pub fn capture_backtrace(value: bool) -> bool {
    CAPTURE_BACKTRACE.with(|cell| {
        let prev = *cell.borrow();
        *cell.borrow_mut() = value;
        prev
    })
}

#[inline]
pub fn forward_panic(value: bool) -> bool {
    FORWARD_PANIC.with(|cell| {
        let prev = *cell.borrow();
        *cell.borrow_mut() = value;
        prev
    })
}

#[inline]
pub fn set_hook() {
    *PANIC_HOOK
}

#[inline]
pub fn rust_backtrace() -> bool {
    *RUST_BACKTRACE
}

#[inline]
pub fn thread_name() -> String {
    THREAD_NAME.with(|cell| cell.clone())
}

#[inline(never)]
fn __panic_marker_start__<F: FnOnce() -> R, R>(f: F) -> R {
    f()
}
