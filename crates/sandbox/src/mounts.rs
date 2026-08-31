use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

use crate::config::MountSpec;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountTable {
    mounts: BTreeMap<String, PlannedMount>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlannedMount {
    VirtualFs,
    HostDirectory,
    BlockDevice,
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
                MountSpec::HostDirectory { path, .. } => {
                    (path.as_str(), PlannedMount::HostDirectory)
                }
                MountSpec::BlockDevice { path } => (path.as_str(), PlannedMount::BlockDevice),
            };

            let canonical_path = Path::new(path)
                .components()
                .collect::<std::path::PathBuf>()
                .to_string_lossy()
                .into_owned();
            if canonical_path == "/" {
                return Err(MountError::new("mount.path must not be /"));
            }

            if table.insert(canonical_path, planned).is_some() {
                return Err(MountError::new(format!("duplicate mount path: {path}")));
            }
        }

        if let Some(block_path) = table.iter().find_map(|(path, mount)| {
            (mount == &PlannedMount::BlockDevice).then_some(path.as_str())
        }) {
            let block = Path::new(block_path);
            let http_ca = Path::new("/run/sandbox/http-ca");
            if block != http_ca && block.starts_with(http_ca) {
                return Err(MountError::new(format!(
                    "block device mount must not be nested beneath /run/sandbox/http-ca: {block_path}"
                )));
            }
            if table.keys().any(|path| {
                let parent = Path::new(path);
                parent != block && block.starts_with(parent)
            }) {
                return Err(MountError::new(format!(
                    "block device mount must not be nested beneath another mount: {block_path}"
                )));
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
    fn rejects_canonically_duplicate_mount_paths() {
        let err = MountTable::plan(&[
            MountSpec::VirtualFs {
                path: "/workspace".to_string(),
                writable: false,
            },
            MountSpec::BlockDevice {
                path: "/workspace/".to_string(),
            },
        ])
        .unwrap_err();

        assert_eq!(err.to_string(), "duplicate mount path: /workspace/");
    }

    #[test]
    fn rejects_mounting_over_root() {
        let err = MountTable::plan(&[MountSpec::VirtualFs {
            path: "/".to_string(),
            writable: false,
        }])
        .unwrap_err();

        assert_eq!(err.to_string(), "mount.path must not be /");

        let err = MountTable::plan(&[MountSpec::VirtualFs {
            path: "////".to_string(),
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

    #[test]
    fn rejects_block_device_nested_beneath_another_mount() {
        let err = MountTable::plan(&[
            MountSpec::VirtualFs {
                path: "/workspace".to_string(),
                writable: false,
            },
            MountSpec::BlockDevice {
                path: "/workspace/disk".to_string(),
            },
        ])
        .unwrap_err();

        assert_eq!(
            err.to_string(),
            "block device mount must not be nested beneath another mount: /workspace/disk"
        );
    }

    #[test]
    fn allows_mounts_nested_beneath_block_device() {
        let table = MountTable::plan(&[
            MountSpec::BlockDevice {
                path: "/workspace".to_string(),
            },
            MountSpec::VirtualFs {
                path: "/workspace/cache".to_string(),
                writable: true,
            },
        ])
        .unwrap();

        assert_eq!(table.get("/workspace"), Some(&PlannedMount::BlockDevice));
        assert_eq!(
            table.get("/workspace/cache"),
            Some(&PlannedMount::VirtualFs)
        );
    }

    #[test]
    fn rejects_block_device_beneath_internal_http_ca_mount() {
        let err = MountTable::plan(&[MountSpec::BlockDevice {
            path: "/run/sandbox/http-ca/state".to_string(),
        }])
        .unwrap_err();

        assert_eq!(
            err.to_string(),
            "block device mount must not be nested beneath /run/sandbox/http-ca: /run/sandbox/http-ca/state"
        );
    }
}
