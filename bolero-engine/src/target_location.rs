use lazy_static::lazy_static;
use std::path::{Path, PathBuf};

#[doc(hidden)]
/// Information about the location of a test target
#[derive(Clone, Debug)]
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

    /// The path to the current test
    pub item_path: String,
}

lazy_static! {
    static ref IS_HARNESSED: bool = is_harnessed();
}

macro_rules! thread_name {
    () => {
        std::thread::current().name().filter(|name| name != &"main")
    };
}

fn is_harnessed() -> bool {
    // if there's a thread name, then libtest has spawned a test thread
    if thread_name!().is_some() {
        return true;
    }

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
                return;
            }
        });

        !is_done
    });

    is_harnessed
}

#[doc(hidden)]
#[macro_export]
macro_rules! __item_path__ {
    () => {
        $crate::target_location::__item_path__(module_path!());
    };
}

#[doc(hidden)]
#[inline(never)]
pub fn __item_path__(module_path: &str) -> String {
    // Initialize the harness check as soon as possible
    let _ = *IS_HARNESSED;

    // cargo-bolero passed the correct test name
    if let Ok(test_name) = std::env::var("BOLERO_TEST_NAME") {
        return test_name;
    }

    // if there's a thread name, then libtest has spawned a test thread
    if let Some(thread_name) = thread_name!() {
        return thread_name.to_string();
    }

    let mut test_name = None;

    // search the backtrace for the current __item_path__ function and get the caller
    // TODO replace this with something better?
    backtrace::trace(|frame| {
        let mut is_done = false;

        backtrace::resolve_frame(frame, |symbol| {
            if let Some(name) = symbol
                .name()
                .map(|name| name.to_string())
                .filter(|name| name.starts_with(module_path))
            {
                let mut parts: Vec<_> = name.split("::").collect();
                parts.pop().expect("unique symbol");

                match parts.last().cloned() {
                    Some("main") if parts.len() == 2 => {
                        parts.pop().expect("main symbol");
                    }
                    Some("{{closure}}") => {
                        parts.pop().expect("unused symbol");
                    }
                    _ => {}
                }

                test_name = Some(if parts.len() == 1 {
                    parts.pop().unwrap().to_string()
                } else {
                    parts[1..].join("::")
                });

                is_done = true;
                return;
            }
        });

        !is_done
    });

    if let Some(test_name) = test_name {
        return test_name;
    }

    panic!(
        r#"
Could not reliably determine a test name located in {:?}.

This is caused by setting `--test-threads=1` and removing debug symbols.

This can be fixed by:

* Increasing the number of test-threads to at least 2
* Explicitly setting the test name:

  ```rust
  #[test]
  fn my_test() {{
      fuzz!(name = "my_test").for_each(|input| {{
          // checks here
      }})
  }}
  ```
* Enabling debug symbols in the project's `Cargo.toml`:

  ```toml
  [profile.bench]
  debug = true
  ```
"#,
        module_path
    );
}

#[test]
fn item_path_test() {
    let test_name = __item_path__!();
    assert_eq!(test_name, "target_location::item_path_test");
}

impl TargetLocation {
    pub fn should_run(&self) -> bool {
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

    fn test_name(&self) -> &str {
        if self.is_harnessed() {
            &self.item_path
        } else {
            // if unharnessed, the test name is just the crate
            self.module_path
        }
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
