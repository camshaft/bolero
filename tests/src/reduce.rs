use crate::{env, Result};
use std::{fs, path::PathBuf};
use xshell::{cmd, Shell};

pub fn test() -> Result {
    let is_nightly = env::rustc_build().map_or(false, |b| b == "nightly");

    Test {
        rustc_bootstrap: !is_nightly,
    }
    .run()?;

    Ok(())
}

struct Test {
    rustc_bootstrap: bool,
}

impl Test {
    fn run(&self) -> Result {
        let sh = Shell::new()?;
        sh.change_dir(env::examples());
        sh.change_dir("reduce");

        // make sure this is up-to-date
        let _ = sh.remove_path("Cargo.lock");

        env::configure_toolchain(&sh);

        let cargo_bolero = env::bins().to_string() + "/target/debug/cargo-bolero";

        let mut args = Vec::new();
        if self.rustc_bootstrap {
            args.push("--rustc-bootstrap".to_string());
        }

        let args = &args;

        let test_name = "tests::test_branches";

        cmd!(sh, "{cargo_bolero} test {test_name} --runs 10000 {args...}").run()?;

        // read the generated corpus
        let corpus_dir =
            env::examples().to_string() + "/reduce/src/__fuzz__/tests__branches/corpus";
        let inputs = self.read_corpus(&corpus_dir).unwrap();
        assert!(!inputs.is_empty());

        let len_before_reduce = inputs.len();

        // create multiple copies of the first input to simulate redundant
        // inputs
        const N: usize = 5;
        let input_name = inputs[0].file_name().unwrap().to_str().unwrap();
        for i in 0..N {
            let _ = fs::copy(
                inputs[0].as_path(),
                format!("{corpus_dir}/{input_name}_{i}"),
            );
        }

        // ensure the copies were created
        let inputs = self.read_corpus(&corpus_dir).unwrap();
        assert_eq!(inputs.len(), len_before_reduce + N);

        // run the reduce command
        cmd!(sh, "{cargo_bolero} reduce {test_name} {args...}").run()?;

        // ensure the redundant inputs were removed
        let inputs = self.read_corpus(&corpus_dir).unwrap();

        assert_eq!(inputs.len(), len_before_reduce);

        Ok(())
    }

    fn read_corpus(&self, corpus_dir: &str) -> Result<Vec<PathBuf>> {
        let inputs: Vec<_> = fs::read_dir(corpus_dir)?
            .filter_map(|entry| Some(entry.ok()?.path()))
            .collect();

        Ok(inputs)
    }
}
