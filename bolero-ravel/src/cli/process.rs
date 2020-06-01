use anyhow::{anyhow, Result};
use std::io::Write;

pub(crate) fn exec(mut cmd: std::process::Command) -> Result<()> {
    cmd.spawn()?.wait()?.status_as_result()
}

pub(crate) trait StatusAsResult {
    type Output;

    fn status_as_result(self) -> Result<Self::Output>;
}

impl StatusAsResult for std::process::ExitStatus {
    type Output = ();

    fn status_as_result(self) -> Result<()> {
        match self.code() {
            Some(0) => Ok(()),
            Some(code) => Err(anyhow!("process exited with status {}", code)),
            None => Err(anyhow!("process exited with no status code")),
        }
    }
}

impl StatusAsResult for std::process::Output {
    type Output = Self;

    fn status_as_result(self) -> Result<Self::Output> {
        if let Err(err) = self.status.status_as_result() {
            std::io::stdout().write_all(&self.stderr)?;
            return Err(err);
        }
        Ok(self)
    }
}
