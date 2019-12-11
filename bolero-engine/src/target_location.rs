use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug)]
pub struct TargetLocation {
    pub manifest_dir: &'static str,
    pub module_path: &'static str,
    pub file: &'static str,
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
