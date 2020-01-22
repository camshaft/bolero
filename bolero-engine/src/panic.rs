use core::{
    cell::RefCell,
    fmt::{Debug, Display},
    panic::PanicInfo,
};
use failure::{Backtrace, Error, Fail};
use lazy_static::lazy_static;
use std::{
    panic::{catch_unwind, AssertUnwindSafe, RefUnwindSafe},
    thread_local,
};

thread_local! {
    static ERROR: RefCell<Option<PanicError>> = RefCell::new(None);
    static CAPTURE_BACKTRACE: RefCell<bool> = RefCell::new(std::env::var("RUST_BACKTRACE")
            .ok()
            .map(|v| v == "1")
            .unwrap_or(false));
    static FORWARD_PANIC: RefCell<bool> = RefCell::new(true);
}

lazy_static! {
    static ref PANIC_HOOK: () = {
        let prev_hook = std::panic::take_hook();

        std::panic::set_hook(Box::new(move |reason| {
            let capture_backtrace = CAPTURE_BACKTRACE.with(|capture| *capture.borrow());
            let panic = PanicError::new(reason.to_string(), capture_backtrace);
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
    message: String,
    backtrace: Option<Backtrace>,
    thread_name: Option<String>,
}

impl Fail for PanicError {
    fn backtrace(&self) -> Option<&Backtrace> {
        self.backtrace.as_ref()
    }
}

impl Display for PanicError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl PanicError {
    pub(crate) fn new(message: String, capture_backtrace: bool) -> Self {
        let backtrace = if capture_backtrace {
            Some(Backtrace::new())
        } else {
            None
        };
        let thread_name = std::thread::current().name().map(String::from);

        Self {
            message,
            backtrace,
            thread_name,
        }
    }
}

pub fn catch<F: RefUnwindSafe + FnOnce() -> Output, Output>(fun: F) -> Result<Output, Error> {
    catch_unwind(AssertUnwindSafe(fun)).map_err(|err| {
        if let Some(err) = fetch_panic() {
            return err.into();
        }
        macro_rules! try_downcast {
            ($ty:ty, $fmt:expr) => {
                if let Some(err) = err.downcast_ref::<$ty>() {
                    return PanicError::new(format!($fmt, err), false).into();
                }
            };
        }
        try_downcast!(PanicInfo, "{}");
        try_downcast!(String, "{}");
        try_downcast!(&'static str, "{}");
        try_downcast!(Box<dyn Display>, "{}");
        try_downcast!(Box<dyn Debug>, "{:?}");
        PanicError::new("thread panicked with unknown error".to_string(), false).into()
    })
}

pub fn fetch_panic() -> Option<PanicError> {
    ERROR.with(|error| error.borrow_mut().take())
}

pub fn capture_backtrace(value: bool) {
    CAPTURE_BACKTRACE.with(|cell| *cell.borrow_mut() = value);
}

pub fn forward_panic(value: bool) {
    FORWARD_PANIC.with(|cell| *cell.borrow_mut() = value);
}

pub fn set_hook() {
    *PANIC_HOOK
}
