use crate::{list::List, project::Project};
use anyhow::{Context, Result};
use std::{
    collections::{hash_map::DefaultHasher, HashMap},
    convert::TryInto,
    hash::{Hash, Hasher},
    path::{Path, PathBuf},
};
use structopt::StructOpt;

const OUTPUT_DIR: &str = "target/fuzz";

/// Builds a tarball for uploading to clusterfuzz
#[derive(Debug, StructOpt)]
pub struct BuildClusterfuzz {
    #[structopt(flatten)]
    project: Project,
}

impl BuildClusterfuzz {
    pub fn exec(&self) -> Result<()> {
        // Create the output directory, and the archive
        std::fs::create_dir_all(OUTPUT_DIR).context("creating clusterfuzz build directory")?;
        let output_path = Path::new(OUTPUT_DIR).join("clusterfuzz.tar");
        let mut tarball = tar::Builder::new(
            std::fs::File::create(&output_path)
                .with_context(|| format!("creating {:?}", output_path))?,
        );

        // Figure out the list of fuzz targets, grouped by which test executable they use
        let targets = List::new(self.project.clone())
            .list()
            .context("listing fuzz targets")?;
        let mut targets_per_exe = HashMap::new();
        for t in targets {
            assert!(
                t.is_harnessed,
                "Non-harnessed tests are not supported for clusterfuzz yet"
            );
            targets_per_exe
                .entry(t.exe)
                .or_insert_with(Vec::new)
                .push(t.test_name);
        }

        // Add all the targets to the archive
        for (list_exe, test_names) in targets_per_exe {
            let mut hasher = DefaultHasher::new();
            list_exe.hash(&mut hasher);
            let hash = hasher.finish();
            let list_bin = Path::new(&list_exe).file_name().unwrap().to_string_lossy();
            let dir = PathBuf::from(format!("{}-{:x}", list_bin, hash));

            let fuzz_exe = crate::libfuzzer::build(self.project.clone(), test_names[0].clone())
                .context("building to-be-fuzzed executable")?;
            // .cargo extension is not an ALLOWED_FUZZ_TARGET_EXTENSIONS for clusterfuzz, so it doesn’t get picked up as a fuzzer
            let fuzz_bin = format!("{}.cargo", fuzz_exe.file_name().unwrap().to_string_lossy());
            tarball
                .append_file(
                    dir.join(&*fuzz_bin),
                    &mut std::fs::File::open(&fuzz_exe)
                        .with_context(|| format!("opening {:?}", &fuzz_exe))?,
                )
                .with_context(|| format!("appending {:?} to {:?}", &fuzz_exe, &output_path))?;

            for test_name in test_names {
                // : is not in VALID_TARGET_NAME_REGEX ; so we don’t use it and make sure to end in _fuzzer so we get picked up as a fuzzer
                let fuzzer_name = format!("{}_fuzzer", test_name.replace(':', "-"));
                let path = dir.join(&fuzzer_name);
                let contents = format!(
                    r#"#!/bin/sh
exec \
env BOLERO_TEST_NAME="{1}" \
    BOLERO_LIBTEST_HARNESS=1 \
    BOLERO_LIBFUZZER_ARGS="$*" \
"$(dirname "$0")/{0}" \
    "{1}" \
    --exact \
    --nocapture \
    --quiet \
    --test-threads 1
"#,
                    fuzz_bin, test_name,
                )
                .into_bytes();
                let mut header = tar::Header::new_gnu();
                header.set_mode(0o555);
                header.set_size(contents.len().try_into().unwrap());
                header.set_cksum();
                tarball
                    .append_data(&mut header, &path, &*contents)
                    .with_context(|| {
                        format!("adding relay script {:?} to {:?}", path, output_path)
                    })?;
            }
            tarball
                .finish()
                .with_context(|| format!("finishing writing {:?}", output_path))?;

            println!("Built the tarball in {:?}", output_path);
        }
        Ok(())
    }
}
