use std::{
    ffi::OsStr,
    path::{Path, PathBuf},
};

/// Information about the location of a test target
#[derive(Clone, Copy, Debug)]
pub struct TargetLocation {
    /// Path to the integration test binary
    pub package_name: &'static str,

    /// Absolute path to the directory of the test target Cargo.toml manifest
    pub manifest_dir: &'static str,

    /// Full module name of the test target
    pub module_path: &'static str,

    /// Absolute path to the test target
    pub file: &'static str,

    /// The line number at which the test target is defined
    pub line: u32,
}

impl TargetLocation {
    pub fn is_exact_match(&self) -> bool {
        let test_name = self.test_name();
        std::env::args().take(2).any(|path| path == test_name)
    }

    pub fn print_if_match(&self) {
        if self.is_exact_match() {
            println!(
                r#"
{{"__bolero_target":"v0.5.0","exe":{:?},"work_dir":{:?},"package_name":{:?},"is_fuzz_target":{:?}}}"#,
                ::std::env::current_exe()
                    .expect("valid current_exe")
                    .display(),
                self.work_dir().expect("valid work_dir").display(),
                &self.package_name,
                self.is_fuzz_target()
            );
        }
    }

    pub fn abs_path(&self) -> Option<PathBuf> {
        let file = Path::new(self.file);

        if let Ok(file) = file.canonicalize() {
            return Some(file);
        }

        Path::new(self.manifest_dir)
            .ancestors()
            .find_map(|ancestor| {
                let path = ancestor.join(file);
                if path.exists() {
                    Some(path)
                } else {
                    None
                }
            })
    }

    /// Returns `true` the location is named `fuzz_target`
    pub fn is_fuzz_target(&self) -> bool {
        Path::new(self.file).file_name() == Some(OsStr::new("fuzz_target.rs"))
    }

    pub fn work_dir(&self) -> Option<PathBuf> {
        let mut work_dir = self.abs_path()?;
        work_dir.pop();

        if self.is_fuzz_target() {
            return Some(work_dir);
        }

        work_dir.push("__fuzz__");
        work_dir.push(self.fuzz_dir());

        Some(work_dir)
    }

    pub fn test_name(&self) -> String {
        if let Ok(name) = std::env::var("__BOLERO_TEST_TARGET") {
            return name;
        }

        if self.is_fuzz_target() {
            return self.module_path.to_string();
        }

        let current_thread = std::thread::current();

        let thread_name = current_thread.name().expect("thread must have a name");

        if thread_name == "main" {
            // TODO support non-threaded mode
            panic!("tests must be run in threaded mode");
        }

        thread_name.to_string()
    }

    fn fuzz_dir(&self) -> String {
        let test_name = self.test_name();
        let mut components: Vec<_> = test_name.split("::").collect();

        let last = components.len() - 1;
        let name = &mut components[last];

        if name.starts_with("test_") || name.starts_with("fuzz_") {
            *name = &name[5..];
        }

        if name.ends_with("_test") || name.ends_with("_fuzz") {
            let len = name.len();
            *name = &name[..(len - 5)];
        }

        components.join("__")
    }
}
