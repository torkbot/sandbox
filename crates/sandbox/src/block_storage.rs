use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::{Arc, Mutex};

use imago::io_buffers::{IoVector, IoVectorMut};
use imago::storage::PreallocateMode;
use imago::storage::drivers::CommonStorageHelper;
use imago::{DynStorage, FormatAccess, Storage};

pub trait CowBlockStore: Send + Sync {
    fn block_size(&self) -> u64;
    fn list_blocks(&self) -> io::Result<HashSet<u64>>;
    fn read_blocks(&self, start: u64, count: u64) -> io::Result<Vec<(u64, Vec<u8>)>>;
    fn write_blocks(&self, chunks: Vec<(u64, Vec<u8>)>) -> io::Result<()>;
    fn flush(&self) -> io::Result<()>;
}

pub struct CowBlockStorage {
    state: Mutex<CowBlockStorageState>,
    helper: CommonStorageHelper,
}

impl fmt::Debug for CowBlockStorage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CowBlockStorage").finish_non_exhaustive()
    }
}

struct CowBlockStorageState {
    base: CowBlockBase,
    size: u64,
    block_size: u64,
    store: Arc<dyn CowBlockStore>,
    store_blocks: HashSet<u64>,
    loaded_store_blocks: HashSet<u64>,
    cached_blocks: HashMap<u64, Vec<u8>>,
    modified_blocks: HashSet<u64>,
}

enum CowBlockBase {
    File(File),
    Storage(FormatAccess<Box<dyn DynStorage>>),
}

impl CowBlockStorage {
    pub fn open(base_path: &Path, store: Arc<dyn CowBlockStore>) -> io::Result<Self> {
        let base = File::open(base_path)?;
        let size = base.metadata()?.len();
        Self::open_base(CowBlockBase::File(base), size, store)
    }

    pub fn open_storage(
        base: FormatAccess<Box<dyn DynStorage>>,
        store: Arc<dyn CowBlockStore>,
    ) -> io::Result<Self> {
        let size = base.size();
        Self::open_base(CowBlockBase::Storage(base), size, store)
    }

    fn open_base(base: CowBlockBase, size: u64, store: Arc<dyn CowBlockStore>) -> io::Result<Self> {
        let block_size = store.block_size();
        if block_size == 0 || block_size % 512 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "COW block size must be a positive multiple of 512 bytes",
            ));
        }

        let store_blocks = store.list_blocks()?;
        Ok(Self {
            state: Mutex::new(CowBlockStorageState {
                base,
                size,
                block_size,
                store,
                store_blocks,
                loaded_store_blocks: HashSet::new(),
                cached_blocks: HashMap::new(),
                modified_blocks: HashSet::new(),
            }),
            helper: CommonStorageHelper::default(),
        })
    }
}

impl fmt::Display for CowBlockStorage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("sandbox COW block storage")
    }
}

impl Storage for CowBlockStorage {
    fn mem_align(&self) -> usize {
        512
    }

    fn req_align(&self) -> usize {
        512
    }

    fn zero_align(&self) -> usize {
        512
    }

    fn discard_align(&self) -> usize {
        512
    }

    fn size(&self) -> io::Result<u64> {
        Ok(self
            .state
            .lock()
            .expect("COW block storage lock poisoned")
            .size)
    }

    async unsafe fn pure_readv(
        &self,
        mut bufv: IoVectorMut<'_>,
        mut offset: u64,
    ) -> io::Result<()> {
        while !bufv.is_empty() {
            let chunk_len = usize::try_from(bufv.len().min(1024 * 1024))
                .map_err(|_| io::Error::other("COW read buffer is too large"))?;
            let (mut head, tail) = bufv.split_at(chunk_len as u64);
            let mut bytes = vec![0; chunk_len];
            self.read_into(&mut bytes, offset).await?;
            head.copy_from_slice(&bytes);
            bufv = tail;
            offset = offset
                .checked_add(chunk_len as u64)
                .ok_or_else(|| io::Error::other("COW read offset overflow"))?;
        }
        Ok(())
    }

    async unsafe fn pure_writev(&self, mut bufv: IoVector<'_>, mut offset: u64) -> io::Result<()> {
        while !bufv.is_empty() {
            let chunk_len = usize::try_from(bufv.len().min(1024 * 1024))
                .map_err(|_| io::Error::other("COW write buffer is too large"))?;
            let (head, tail) = bufv.split_at(chunk_len as u64);
            let mut bytes = vec![0; chunk_len];
            head.copy_into_slice(&mut bytes);
            self.write_from(&bytes, offset).await?;
            bufv = tail;
            offset = offset
                .checked_add(chunk_len as u64)
                .ok_or_else(|| io::Error::other("COW write offset overflow"))?;
        }
        Ok(())
    }

    async unsafe fn pure_write_zeroes(&self, offset: u64, length: u64) -> io::Result<()> {
        self.write_zeroes(offset, length).await
    }

    async unsafe fn pure_write_allocated_zeroes(&self, offset: u64, length: u64) -> io::Result<()> {
        self.write_zeroes(offset, length).await
    }

    async unsafe fn pure_discard(&self, offset: u64, length: u64) -> io::Result<()> {
        self.write_zeroes(offset, length).await
    }

    async fn flush(&self) -> io::Result<()> {
        let (store, chunks) = {
            let state = self.state.lock().expect("COW block storage lock poisoned");
            let chunks = state
                .modified_blocks
                .iter()
                .filter_map(|index| {
                    state
                        .cached_blocks
                        .get(index)
                        .map(|data| (*index, data.clone()))
                })
                .collect::<Vec<_>>();
            (state.store.clone(), chunks)
        };
        if !chunks.is_empty() {
            store.write_blocks(chunks.clone())?;
        }
        store.flush()?;
        let mut state = self.state.lock().expect("COW block storage lock poisoned");
        for (index, flushed) in chunks {
            if state
                .cached_blocks
                .get(&index)
                .is_some_and(|current| current == &flushed)
            {
                state.modified_blocks.remove(&index);
            }
        }
        Ok(())
    }

    async fn sync(&self) -> io::Result<()> {
        self.flush().await
    }

    async unsafe fn invalidate_cache(&self) -> io::Result<()> {
        Ok(())
    }

    fn get_storage_helper(&self) -> &CommonStorageHelper {
        &self.helper
    }

    async fn resize(&self, new_size: u64, _prealloc_mode: PreallocateMode) -> io::Result<()> {
        let mut state = self.state.lock().expect("COW block storage lock poisoned");
        if new_size > state.size {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "COW root storage cannot grow beyond the base image size",
            ));
        }
        state.size = new_size;
        Ok(())
    }
}

impl CowBlockStorage {
    async fn read_into(&self, output: &mut [u8], offset: u64) -> io::Result<()> {
        let mut state = self.state.lock().expect("COW block storage lock poisoned");
        if offset >= state.size {
            output.fill(0);
            return Ok(());
        }

        let readable = output.len().min((state.size - offset) as usize);
        state
            .base
            .read_exact_at(&mut output[..readable], offset)
            .await?;
        if readable < output.len() {
            output[readable..].fill(0);
        }
        state.overlay_range(output, offset)
    }

    async fn write_from(&self, input: &[u8], offset: u64) -> io::Result<()> {
        let mut state = self.state.lock().expect("COW block storage lock poisoned");
        let end = offset
            .checked_add(input.len() as u64)
            .ok_or_else(|| io::Error::other("COW write offset overflow"))?;
        if end > state.size {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "COW root storage write extends beyond base image",
            ));
        }
        state.write_range(input, offset).await
    }

    async fn write_zeroes(&self, offset: u64, length: u64) -> io::Result<()> {
        const ZERO_CHUNK_SIZE: usize = 1024 * 1024;
        let mut remaining = length;
        let mut next_offset = offset;
        let zeroes = vec![0; ZERO_CHUNK_SIZE];
        while remaining > 0 {
            let chunk_len = remaining.min(ZERO_CHUNK_SIZE as u64) as usize;
            self.write_from(&zeroes[..chunk_len], next_offset).await?;
            remaining -= chunk_len as u64;
            next_offset = next_offset
                .checked_add(chunk_len as u64)
                .ok_or_else(|| io::Error::other("COW zero offset overflow"))?;
        }
        Ok(())
    }
}

impl CowBlockStorageState {
    fn overlay_range(&mut self, output: &mut [u8], offset: u64) -> io::Result<()> {
        let first_block = offset / self.block_size;
        let last_block = (offset + output.len() as u64 - 1) / self.block_size;
        self.load_store_blocks(first_block, last_block)?;
        for block_index in first_block..=last_block {
            let Some(block) = self.cached_blocks.get(&block_index) else {
                continue;
            };
            let block_start = block_index * self.block_size;
            let range_start = offset.max(block_start);
            let range_end = (offset + output.len() as u64).min(block_start + self.block_size);
            if range_start >= range_end {
                continue;
            }
            let output_start = (range_start - offset) as usize;
            let block_start = (range_start - block_start) as usize;
            let len = (range_end - range_start) as usize;
            output[output_start..output_start + len]
                .copy_from_slice(&block[block_start..block_start + len]);
        }
        Ok(())
    }

    async fn write_range(&mut self, input: &[u8], offset: u64) -> io::Result<()> {
        let first_block = offset / self.block_size;
        let last_block = (offset + input.len() as u64 - 1) / self.block_size;
        self.load_store_blocks(first_block, last_block)?;
        for block_index in first_block..=last_block {
            let block_start = block_index * self.block_size;
            let range_start = offset.max(block_start);
            let range_end = (offset + input.len() as u64).min(block_start + self.block_size);
            if range_start >= range_end {
                continue;
            }
            if !self.cached_blocks.contains_key(&block_index) {
                let mut block = vec![0; self.block_size as usize];
                let readable = self.size.saturating_sub(block_start).min(self.block_size) as usize;
                if readable > 0 {
                    self.base
                        .read_exact_at(&mut block[..readable], block_start)
                        .await?;
                }
                self.cached_blocks.insert(block_index, block);
                self.loaded_store_blocks.insert(block_index);
            }
            let block = self.cached_blocks.get_mut(&block_index).unwrap();
            let input_start = (range_start - offset) as usize;
            let block_offset = (range_start - block_start) as usize;
            let len = (range_end - range_start) as usize;
            block[block_offset..block_offset + len]
                .copy_from_slice(&input[input_start..input_start + len]);
            self.modified_blocks.insert(block_index);
            self.store_blocks.insert(block_index);
        }
        Ok(())
    }

    fn load_store_blocks(&mut self, first_block: u64, last_block: u64) -> io::Result<()> {
        let mut block = first_block;
        while block <= last_block {
            while block <= last_block
                && (!self.store_blocks.contains(&block)
                    || self.loaded_store_blocks.contains(&block)
                    || self.cached_blocks.contains_key(&block))
            {
                block += 1;
            }
            if block > last_block {
                break;
            }
            let start = block;
            while block <= last_block
                && self.store_blocks.contains(&block)
                && !self.loaded_store_blocks.contains(&block)
                && !self.cached_blocks.contains_key(&block)
            {
                block += 1;
            }
            let count = block - start;
            let mut returned_blocks = HashSet::new();
            for (index, data) in self.store.read_blocks(start, count)? {
                if index < start || index >= start + count {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "COW block store returned a block outside the requested range",
                    ));
                }
                if data.len() > self.block_size as usize {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "COW block store returned a chunk larger than block size",
                    ));
                }
                let mut block = vec![0; self.block_size as usize];
                block[..data.len()].copy_from_slice(&data);
                self.cached_blocks.insert(index, block);
                returned_blocks.insert(index);
            }
            for expected in start..start + count {
                if !returned_blocks.contains(&expected) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "COW block store omitted a listed block",
                    ));
                }
            }
            self.loaded_store_blocks.extend(start..start + count);
        }
        Ok(())
    }
}

impl CowBlockBase {
    async fn read_exact_at(&mut self, output: &mut [u8], offset: u64) -> io::Result<()> {
        match self {
            Self::File(file) => {
                file.seek(SeekFrom::Start(offset))?;
                file.read_exact(output)
            }
            Self::Storage(storage) => storage.read(output, offset).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::fs;
    use std::future::Future;
    use std::pin::pin;
    use std::sync::Mutex;
    use std::task::{Context, Poll, Waker};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[derive(Debug)]
    struct TestBlockStore {
        block_size: u64,
        blocks: Mutex<HashMap<u64, Vec<u8>>>,
    }

    impl CowBlockStore for TestBlockStore {
        fn block_size(&self) -> u64 {
            self.block_size
        }

        fn list_blocks(&self) -> io::Result<HashSet<u64>> {
            Ok(self.blocks.lock().unwrap().keys().copied().collect())
        }

        fn read_blocks(&self, start: u64, count: u64) -> io::Result<Vec<(u64, Vec<u8>)>> {
            let blocks = self.blocks.lock().unwrap();
            Ok((start..start + count)
                .filter_map(|index| blocks.get(&index).map(|data| (index, data.clone())))
                .collect())
        }

        fn write_blocks(&self, chunks: Vec<(u64, Vec<u8>)>) -> io::Result<()> {
            let mut blocks = self.blocks.lock().unwrap();
            for (index, data) in chunks {
                blocks.insert(index, data);
            }
            Ok(())
        }

        fn flush(&self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn load_store_blocks_rejects_missing_listed_blocks() {
        let path = temp_base_image_path();
        fs::write(&path, [0_u8; 8192]).unwrap();
        let base = File::open(&path).unwrap();
        let store = Arc::new(TestBlockStore {
            block_size: 4096,
            blocks: Mutex::new(HashMap::new()),
        });
        let mut state = CowBlockStorageState {
            base: CowBlockBase::File(base),
            size: 8192,
            block_size: 4096,
            store,
            store_blocks: HashSet::from([1]),
            loaded_store_blocks: HashSet::new(),
            cached_blocks: HashMap::new(),
            modified_blocks: HashSet::new(),
        };

        let error = state.load_store_blocks(1, 1).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(error.to_string(), "COW block store omitted a listed block");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn overlapping_unflushed_writes_do_not_reload_from_store() {
        let path = temp_base_image_path();
        fs::write(&path, [0_u8; 8192]).unwrap();
        let base = File::open(&path).unwrap();
        let store = Arc::new(TestBlockStore {
            block_size: 4096,
            blocks: Mutex::new(HashMap::new()),
        });
        let mut state = CowBlockStorageState {
            base: CowBlockBase::File(base),
            size: 8192,
            block_size: 4096,
            store,
            store_blocks: HashSet::new(),
            loaded_store_blocks: HashSet::new(),
            cached_blocks: HashMap::new(),
            modified_blocks: HashSet::new(),
        };

        block_on_ready(state.write_range(&[1; 4096], 4096)).unwrap();
        block_on_ready(state.write_range(&[2; 512], 4096)).unwrap();

        assert_eq!(state.cached_blocks.get(&1).unwrap()[..512], [2; 512]);
        assert_eq!(state.cached_blocks.get(&1).unwrap()[512..], [1; 3584]);
        let _ = fs::remove_file(path);
    }

    fn temp_base_image_path() -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        env::temp_dir().join(format!("sandbox-cow-block-storage-test-{nanos}.img"))
    }

    fn block_on_ready<T>(future: impl Future<Output = T>) -> T {
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        let mut future = pin!(future);
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("test future unexpectedly pending"),
        }
    }
}
