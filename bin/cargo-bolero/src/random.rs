use crate::{exec, test, Selection};
use anyhow::Result;

const FLAGS: &[&str] = &["--cfg fuzzing_random"];

pub(crate) fn test(selection: &Selection, test_args: &test::Args) -> Result<()> {
    let test_target = selection.test_target(FLAGS, "random")?;

    let mut cmd = test_target.command();

    macro_rules! optional_arg {
        ($arg:ident, $env:expr) => {
            if let Some(v) = test_args.$arg {
                cmd.env($env, v.to_string());
            }
        };
    }

    optional_arg!(seed, "BOLERO_RANDOM_SEED");
    optional_arg!(runs, "BOLERO_RANDOM_ITERATIONS");
    optional_arg!(max_input_length, "BOLERO_RANDOM_MAX_LEN");

    // TODO implement other options
    /*

    /// Run the engine for a specified duration. If unspecified
    /// it will continue until manually stopped.
    #[structopt(short = "T")]
    pub time: Option<Duration>,

    /// Maximum amount of time to run a test target before
    /// failing
    #[structopt(short, long, default_value = "10s")]
    pub timeout: Duration,
    */

    exec(cmd)?;

    Ok(())
}
