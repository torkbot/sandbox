use std::collections::BTreeMap;
use std::fmt;

use crate::config::MountSpec;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountTable {
    mounts: BTreeMap<String, PlannedMount>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlannedMount {
    SqliteFs { name: String },
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
                MountSpec::SqliteFs { path, name } => {
                    (path.as_str(), PlannedMount::SqliteFs { name: name.clone() })
                }
                MountSpec::VirtualFs { path } => (path.as_str(), PlannedMount::VirtualFs),
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
    fn plans_sqlite_and_virtual_mounts_by_guest_path() {
        let table = MountTable::plan(&[
            MountSpec::SqliteFs {
                path: "/workspace".to_string(),
                name: "workspace".to_string(),
            },
            MountSpec::VirtualFs {
                path: "/sandbox".to_string(),
            },
        ])
        .unwrap();

        assert_eq!(table.len(), 2);
        assert_eq!(
            table.get("/workspace"),
            Some(&PlannedMount::SqliteFs {
                name: "workspace".to_string(),
            }),
        );
        assert_eq!(table.get("/sandbox"), Some(&PlannedMount::VirtualFs));
    }

    #[test]
    fn rejects_duplicate_mount_paths() {
        let err = MountTable::plan(&[
            MountSpec::VirtualFs {
                path: "/sandbox".to_string(),
            },
            MountSpec::VirtualFs {
                path: "/sandbox".to_string(),
            },
        ])
        .unwrap_err();

        assert_eq!(err.to_string(), "duplicate mount path: /sandbox");
    }

    #[test]
    fn rejects_mounting_over_root() {
        let err = MountTable::plan(&[MountSpec::VirtualFs {
            path: "/".to_string(),
        }])
        .unwrap_err();

        assert_eq!(err.to_string(), "mount.path must not be /");
    }
}
