use std::path::{Path, PathBuf};

/// Information about the location of a test target
#[derive(Clone, Copy, Debug)]
pub struct TargetLocation {
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
}
