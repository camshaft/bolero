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
    pub item_path: &'static str,

    /// The name of the test
    pub test_name: Option<String>,
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
        let test_name = self.item_path();
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
            self.item_path(),
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
        if let Some(test_name) = self.test_name.as_ref() {
            work_dir.push(test_name);
        } else {
            work_dir.push(self.fuzz_dir());
        }

        Some(work_dir)
    }

    pub fn is_harnessed(&self) -> bool {
        is_harnessed(self.item_path)
    }

    fn fuzz_dir(&self) -> String {
        let test_name = self.item_path();
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

    fn item_path(&self) -> String {
        format_symbol_name(&self.item_path)
    }
}

fn is_harnessed(name: &str) -> bool {
    // only harnessed tests spawn threads
    if std::thread::current()
        .name()
        .filter(|name| name != &"main")
        .is_some()
    {
        return true;
    }

    let mut parts: Vec<_> = name.split("::").collect();

    // remove parts up to the path probe
    while parts.pop().expect("empty path") != "__bolero_item_path__" {}

    // fuzz targets defined in main are not harnessed
    !matches!(
        parts.last().cloned(),
        Some("main") if parts.len() == 2
    )
}

#[doc(hidden)]
#[macro_export]
macro_rules! __item_path__ {
    () => {{
        fn __bolero_item_path__() {}
        fn __resolve_item_path__<T>(_: T) -> &'static str {
            ::core::any::type_name::<T>()
        }
        __resolve_item_path__(__bolero_item_path__)
    }};
}

#[test]
fn item_path_test() {
    let test_name = format_symbol_name(__item_path__!());
    assert_eq!(test_name, "target_location::item_path_test");
}

fn format_symbol_name(name: &str) -> String {
    let mut parts: Vec<_> = name.split("::").collect();

    // remove parts up to the path probe
    while parts.pop().expect("empty path") != "__bolero_item_path__" {}

    match parts.last().cloned() {
        Some("main") if parts.len() == 2 => {
            parts.pop().expect("main symbol");
        }
        Some("{{closure}}") => {
            parts.pop().expect("unused symbol");
        }
        _ => {}
    }

    if parts.len() == 1 {
        parts.pop().unwrap().to_string()
    } else {
        parts[1..].join("::")
    }
}

#[test]
fn format_symbol_name_test() {
    assert_eq!(
        format_symbol_name("crate::main::__bolero_item_path__::123"),
        "crate"
    );
    assert_eq!(
        format_symbol_name("crate::test::__bolero_item_path__::123"),
        "test"
    );
    assert_eq!(
        format_symbol_name("crate::test::{{closure}}::__bolero_item_path__::123"),
        "test"
    );
    assert_eq!(
        format_symbol_name("crate::nested::test::__bolero_item_path__::123"),
        "nested::test"
    );
}
