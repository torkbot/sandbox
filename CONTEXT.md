# Sandbox

Sandbox runs processes inside isolated virtual machines while presenting caller-selected host resources through explicit boundaries. This language distinguishes the guest's filesystem meaning from the host storage used to realize it.

## Language

**Host-directory bind**:
A live view of an existing host directory exposed to the guest through virtio-fs rather than copied into guest-owned storage.
_Avoid_: Shared folder, synchronized directory

**Native inode**:
An inode whose guest ownership and mode are derived from current host metadata through the VM's identity mapping.
_Avoid_: Unmanaged file, passthrough inode

**Adopted inode**:
An inode whose stable guest ownership, mode, and file capabilities are governed by Sandbox metadata rather than reconstructed from host identity.
_Avoid_: Virtual file, managed file

**Guest authority metadata**:
The guest UID, GID, mode, and file-capability state that determines an adopted inode's Linux identity and privilege behavior.
_Avoid_: Override stat, fake permissions

**Backing permissions**:
The physical host permissions that constrain the sandbox host process's access to a host-directory bind independently of guest authority metadata.
_Avoid_: Guest mode, effective permissions
