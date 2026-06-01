use std::io;
use std::path::Path;
use std::sync::Arc;

use imago::qcow2::Qcow2;
use imago::{
    DenyImplicitOpenGate, DynStorage, FormatAccess, FormatCreateBuilder, FormatDriverBuilder,
    PermissiveImplicitOpenGate, Storage,
};

use crate::block_storage::{BlockStoreImageStorage, CowBlockStorage, CowBlockStore};

pub struct Qcow2FlattenOptions {
    pub cluster_size: usize,
}

pub struct Qcow2FlattenResult {
    pub size_bytes: u64,
}

pub async fn flatten_rootfs_to_qcow2(
    base_path: &Path,
    overlay_store: Arc<dyn CowBlockStore>,
    dest_store: Arc<dyn CowBlockStore>,
    options: Qcow2FlattenOptions,
) -> io::Result<Qcow2FlattenResult> {
    let base_qcow2 = Qcow2::<Box<dyn DynStorage>>::builder_path(base_path)
        .open(PermissiveImplicitOpenGate::default())
        .await?;
    let base = FormatAccess::new(base_qcow2);
    let source_size = base.size();
    let max_dirty_bytes = (64 * 1024 * 1024).max(overlay_store.block_size());
    let source_storage = CowBlockStorage::open_storage(base, overlay_store, max_dirty_bytes)?;
    let dest_storage = BlockStoreImageStorage::new(dest_store, 0)?;
    let dest_size = dest_storage.clone();
    let dest_qcow2 =
        Qcow2::<BlockStoreImageStorage, FormatAccess<BlockStoreImageStorage>>::create_builder(
            dest_storage,
        )
        .size(source_size)
        .cluster_size(options.cluster_size)
        .create_open(DenyImplicitOpenGate::default(), |image| {
            Ok(
                Qcow2::<BlockStoreImageStorage, FormatAccess<BlockStoreImageStorage>>::builder(
                    image,
                )
                .backing(None)
                .write(true),
            )
        })
        .await?;
    let dest = FormatAccess::new(dest_qcow2);

    let mut offset = 0;
    let mut buffer = vec![0; 1024 * 1024];
    while offset < source_size {
        let len = buffer.len().min((source_size - offset) as usize);
        source_storage.read_into(&mut buffer[..len], offset).await?;
        if buffer[..len].iter().all(|byte| *byte == 0) {
            dest.write_zeroes(offset, len as u64).await?;
        } else {
            dest.write(&buffer[..len], offset).await?;
        }
        offset += len as u64;
    }
    dest.flush().await?;

    Ok(Qcow2FlattenResult {
        size_bytes: dest_size.size()?,
    })
}
