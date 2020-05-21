use crate::panic::PanicError;
use anyhow::Error;

/// Trait that turns the test return value into a `Result`
pub trait IntoTestResult {
    fn into_test_result(self) -> Result<(), PanicError>;
}

impl IntoTestResult for () {
    fn into_test_result(self) -> Result<(), PanicError> {
        Ok(())
    }
}

impl IntoTestResult for bool {
    fn into_test_result(self) -> Result<(), PanicError> {
        if self {
            Ok(())
        } else {
            Err(PanicError::new("test returned `false`".to_string()))
        }
    }
}

impl<T, E: Into<Error>> IntoTestResult for Result<T, E> {
    fn into_test_result(self) -> Result<(), PanicError> {
        if let Err(err) = self {
            let err = err.into();
            Err(PanicError::new(err.to_string()))
        } else {
            Ok(())
        }
    }
}

impl<T> IntoTestResult for Option<T> {
    fn into_test_result(self) -> Result<(), PanicError> {
        if self.is_none() {
            Err(PanicError::new("test returned `None`".to_string()))
        } else {
            Ok(())
        }
    }
}
