use core::fmt::{self, Debug, Display};
use std::panic::RefUnwindSafe;

#[derive(Debug)]
#[allow(dead_code)]
pub struct PanicError {
    pub(crate) message: String,
    pub(crate) location: Option<String>,
    pub(crate) backtrace: Option<Backtrace>,
    pub(crate) thread_name: String,
}

impl Display for PanicError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "PANIC")?;
        Ok(())
    }
}

impl std::error::Error for PanicError {}

impl PanicError {
    pub(crate) fn new(message: String) -> Self {
        Self {
            message,
            location: None,
            backtrace: None,
            thread_name: thread_name(),
        }
    }
}

pub fn catch<F: RefUnwindSafe + FnOnce() -> Output, Output>(fun: F) -> Result<Output, PanicError> {
    Ok(fun())
}

pub fn take_panic() -> Option<PanicError> {
    None
}

pub fn capture_backtrace(_value: bool) -> bool {
    false
}

pub fn forward_panic(_value: bool) -> bool {
    false
}

pub fn set_hook() {
    // no-op
}

pub fn rust_backtrace() -> bool {
    false
}

pub fn thread_name() -> String {
    String::from("main")
}

#[derive(Debug)]
pub struct Backtrace(());

impl Display for Backtrace {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "backtrace")?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct BacktraceFrame(());
