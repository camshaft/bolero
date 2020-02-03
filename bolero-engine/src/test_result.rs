use failure::{bail, Error};

/// Trait that turns the test return value into a `Result`
pub trait IntoTestResult {
    fn into_test_result(self) -> Result<(), Error>;
}

impl IntoTestResult for () {
    fn into_test_result(self) -> Result<(), Error> {
        Ok(())
    }
}

impl IntoTestResult for bool {
    fn into_test_result(self) -> Result<(), Error> {
        if self {
            Ok(())
        } else {
            bail!("test returned `false`")
        }
    }
}

impl<T, E: Into<Error>> IntoTestResult for Result<T, E> {
    fn into_test_result(self) -> Result<(), Error> {
        if let Err(err) = self {
            Err(err.into())
        } else {
            Ok(())
        }
    }
}

impl<T> IntoTestResult for Option<T> {
    fn into_test_result(self) -> Result<(), Error> {
        if self.is_none() {
            bail!("test returned `None`")
        } else {
            Ok(())
        }
    }
}
