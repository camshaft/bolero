use anyhow::{anyhow, Error, Result};

/// Trait that turns the test return value into a `Result`
pub trait IntoTestResult {
    fn into_test_result(self) -> Result<()>;
}

impl IntoTestResult for () {
    fn into_test_result(self) -> Result<()> {
        Ok(())
    }
}

impl IntoTestResult for bool {
    fn into_test_result(self) -> Result<()> {
        if self {
            Ok(())
        } else {
            Err(anyhow!("test returned `false`"))
        }
    }
}

impl<T, E: Into<Error>> IntoTestResult for Result<T, E> {
    fn into_test_result(self) -> Result<()> {
        if let Err(err) = self {
            Err(err.into())
        } else {
            Ok(())
        }
    }
}

impl<T> IntoTestResult for Option<T> {
    fn into_test_result(self) -> Result<()> {
        if self.is_none() {
            Err(anyhow!("test returned `None`"))
        } else {
            Ok(())
        }
    }
}
