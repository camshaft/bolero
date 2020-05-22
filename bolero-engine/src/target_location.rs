use lazy_static::lazy_static;
use std::path::{Path, PathBuf};

#[doc(hidden)]
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

lazy_static! {
    static ref IS_HARNESSED: bool = is_harnessed();
}

fn is_harnessed() -> bool {
    let mut is_harnessed = false;

    // search the stack to find if libtest was included
    // TODO find a better way to do this
    backtrace::trace(|frame| {
        let mut is_done = false;

        backtrace::resolve_frame(frame, |symbol| {
            if symbol
                .filename()
                .and_then(|file| file.to_str())
                .map(|file| file.ends_with("src/libtest/lib.rs"))
                .unwrap_or(false)
            {
                is_harnessed = true;
                is_done = true;
            }
        });

        !is_done
    });

    is_harnessed
}

impl TargetLocation {
    pub fn should_run(&self) -> bool {
        // cargo-bolero needs to compile everything
        if ::std::env::var("CARGO_BOLERO_BOOTSTRAP").is_ok() {
            return false;
        }

        // cargo-bolero needs to resolve information about the target
        if let Ok(mode) = ::std::env::var("CARGO_BOLERO_SELECT") {
            match mode.as_str() {
                "all" => self.print(),
                "one" if self.is_exact_match() => self.print(),
                _ => {}
            }
            return false;
        }

        true
    }

    fn is_exact_match(&self) -> bool {
        let test_name = self.test_name();
        std::env::args().take(2).any(|path| path == test_name)
    }

    fn print(&self) {
        println!(
            r#"
{{"__bolero_target":"v0.5.0","exe":{:?},"work_dir":{:?},"package_name":{:?},"is_harnessed":{:?},"test_name":{:?}}}"#,
            ::std::env::current_exe()
                .expect("valid current_exe")
                .display(),
            self.work_dir().expect("valid work_dir").display(),
            &self.package_name,
            self.is_harnessed(),
            self.test_name(),
        );
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

    pub fn work_dir(&self) -> Option<PathBuf> {
        let mut work_dir = self.abs_path()?;
        work_dir.pop();

        if !self.is_harnessed() {
            return Some(work_dir);
        }

        work_dir.push("__fuzz__");
        work_dir.push(self.fuzz_dir());

        Some(work_dir)
    }

    fn test_name(&self) -> String {
        if !self.is_harnessed() {
            return self.module_path.to_string();
        }

        let current_thread = std::thread::current();

        let thread_name = current_thread.name().expect("thread must have a name");

        if thread_name == "main" {
            panic!("test selection must be run in threaded mode");
        }

        thread_name.to_string()
    }

    pub fn is_harnessed(&self) -> bool {
        *IS_HARNESSED
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
