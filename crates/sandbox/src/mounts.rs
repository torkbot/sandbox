use std::collections::BTreeMap;
use std::fmt;

use crate::config::MountSpec;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountTable {
    mounts: BTreeMap<String, PlannedMount>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlannedMount {
    VirtualFs,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountError {
    message: String,
}

impl MountTable {
    pub fn plan(mounts: &[MountSpec]) -> Result<Self, MountError> {
        let mut table = BTreeMap::new();

        for mount in mounts {
            let (path, planned) = match mount {
                MountSpec::VirtualFs { path, .. } => (path.as_str(), PlannedMount::VirtualFs),
            };

            if path == "/" {
                return Err(MountError::new("mount.path must not be /"));
            }

            if table.insert(path.to_string(), planned).is_some() {
                return Err(MountError::new(format!("duplicate mount path: {path}")));
            }
        }

        Ok(Self { mounts: table })
    }

    pub fn get(&self, path: &str) -> Option<&PlannedMount> {
        self.mounts.get(path)
    }

    pub fn len(&self) -> usize {
        self.mounts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.mounts.is_empty()
    }
}

impl MountError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for MountError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for MountError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plans_virtual_mounts_by_guest_path() {
        let table = MountTable::plan(&[MountSpec::VirtualFs {
            path: "/sandbox".to_string(),
            writable: false,
        }])
        .unwrap();

        assert_eq!(table.len(), 1);
        assert_eq!(table.get("/sandbox"), Some(&PlannedMount::VirtualFs));
    }

    #[test]
    fn rejects_duplicate_mount_paths() {
        let err = MountTable::plan(&[
            MountSpec::VirtualFs {
                path: "/sandbox".to_string(),
                writable: false,
            },
            MountSpec::VirtualFs {
                path: "/sandbox".to_string(),
                writable: true,
            },
        ])
        .unwrap_err();

        assert_eq!(err.to_string(), "duplicate mount path: /sandbox");
    }

    #[test]
    fn rejects_mounting_over_root() {
        let err = MountTable::plan(&[MountSpec::VirtualFs {
            path: "/".to_string(),
            writable: false,
        }])
        .unwrap_err();

        assert_eq!(err.to_string(), "mount.path must not be /");
    }

    #[test]
    fn allows_nested_mount_paths_for_ordered_guest_mounts() {
        let table = MountTable::plan(&[
            MountSpec::VirtualFs {
                path: "/workspace".to_string(),
                writable: false,
            },
            MountSpec::VirtualFs {
                path: "/workspace/cache".to_string(),
                writable: true,
            },
        ])
        .unwrap();

        assert_eq!(table.len(), 2);
        assert_eq!(table.get("/workspace"), Some(&PlannedMount::VirtualFs));
        assert_eq!(
            table.get("/workspace/cache"),
            Some(&PlannedMount::VirtualFs)
        );
    }
}
