use crate::{env, Result};
use xshell::{cmd, Shell};

pub fn test() -> Result {
    // The examples exercise the library through the fuzzing engines; they are dev tooling, not part
    // of the library's MSRV contract, so skip them on an old (MSRV-probe) toolchain.
    if !env::runs_tooling_stages() {
        eprintln!("skipping examples on this toolchain (library-MSRV-only row)");
        return Ok(());
    }

    Test {}.run()?;

    Ok(())
}

struct Test {}

impl Test {
    fn run(&self) -> Result {
        let sh = Shell::new()?;
        sh.change_dir(env::examples());

        env::configure_toolchain(&sh);

        for example in std::fs::read_dir(sh.current_dir())?.flatten() {
            if !example.path().is_dir() {
                continue;
            }

            let _dir = sh.push_dir(example.path());

            // make sure this is up-to-date (MSRV-aware for older matrix toolchains)
            env::regenerate_lockfile(&sh)?;

            cmd!(sh, "cargo test").run()?;

            // make sure bolero still works with a single thread
            cmd!(sh, "cargo test -- --test-threads=1").run()?;
        }

        Ok(())
    }
}
