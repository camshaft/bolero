use crate::panic::PanicError;
use anyhow::Error;

/// Trait that turns the test return value into a `Result`
pub trait IntoResult {
    fn into_result(self) -> Result<(), PanicError>;
}

impl IntoResult for () {
    fn into_result(self) -> Result<(), PanicError> {
        Ok(())
    }
}

impl IntoResult for bool {
    fn into_result(self) -> Result<(), PanicError> {
        if self {
            Ok(())
        } else {
            Err(PanicError::new("test returned `false`".to_string()))
        }
    }
}

impl<T, E: Into<Error>> IntoResult for Result<T, E> {
    fn into_result(self) -> Result<(), PanicError> {
        if let Err(err) = self {
            let err = err.into();
            Err(PanicError::new(err.to_string()))
        } else {
            Ok(())
        }
    }
}

impl<T> IntoResult for Option<T> {
    fn into_result(self) -> Result<(), PanicError> {
        if self.is_none() {
            Err(PanicError::new("test returned `None`".to_string()))
        } else {
            Ok(())
        }
    }
}
