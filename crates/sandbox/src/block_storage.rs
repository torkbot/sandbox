use std::collections::{HashMap, HashSet, VecDeque};
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
    clean_cached_blocks: HashSet<u64>,
    clean_cache_order: VecDeque<u64>,
    max_dirty_bytes: u64,
}

enum CowBlockBase {
    File(File),
    Storage(FormatAccess<Box<dyn DynStorage>>),
}

impl CowBlockStorage {
    pub fn open(
        base_path: &Path,
        store: Arc<dyn CowBlockStore>,
        max_dirty_bytes: u64,
    ) -> io::Result<Self> {
        let base = File::open(base_path)?;
        let size = base.metadata()?.len();
        Self::open_base(CowBlockBase::File(base), size, store, max_dirty_bytes)
    }

    pub fn open_storage(
        base: FormatAccess<Box<dyn DynStorage>>,
        store: Arc<dyn CowBlockStore>,
        max_dirty_bytes: u64,
    ) -> io::Result<Self> {
        let size = base.size();
        Self::open_base(CowBlockBase::Storage(base), size, store, max_dirty_bytes)
    }

    fn open_base(
        base: CowBlockBase,
        size: u64,
        store: Arc<dyn CowBlockStore>,
        max_dirty_bytes: u64,
    ) -> io::Result<Self> {
        let block_size = store.block_size();
        if block_size == 0 || block_size % 512 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "COW block size must be a positive multiple of 512 bytes",
            ));
        }
        if max_dirty_bytes < block_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "COW max dirty bytes must be at least the block size",
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
                clean_cached_blocks: HashSet::new(),
                clean_cache_order: VecDeque::new(),
                max_dirty_bytes,
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
            let chunk_len = usize::try_from(bufv.len().min(self.max_write_chunk_len()?))
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
                state.mark_clean_cached(index);
            }
        }
        state.evict_clean_cache();
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
        let should_flush = {
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
            state.write_range(input, offset).await?;
            state.dirty_bytes() >= state.max_dirty_bytes
        };
        if should_flush {
            self.flush().await?;
        }
        Ok(())
    }

    fn max_write_chunk_len(&self) -> io::Result<u64> {
        let state = self.state.lock().expect("COW block storage lock poisoned");
        let available_dirty_bytes = state
            .max_dirty_bytes
            .saturating_sub(state.dirty_bytes())
            .max(state.block_size);
        Ok((1024 * 1024).min(available_dirty_bytes))
    }

    async fn write_zeroes(&self, offset: u64, length: u64) -> io::Result<()> {
        let mut remaining = length;
        let mut next_offset = offset;
        while remaining > 0 {
            let chunk_len = remaining.min(self.max_write_chunk_len()?) as usize;
            let zeroes = vec![0; chunk_len];
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
    fn dirty_bytes(&self) -> u64 {
        self.modified_blocks.len() as u64 * self.block_size
    }

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
            self.clean_cached_blocks.remove(&block_index);
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
                self.mark_clean_cached(index);
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
            self.evict_clean_cache();
        }
        Ok(())
    }

    fn mark_clean_cached(&mut self, index: u64) {
        if !self.modified_blocks.contains(&index) && self.cached_blocks.contains_key(&index) {
            if self.clean_cached_blocks.insert(index) {
                self.clean_cache_order.push_back(index);
            }
        }
    }

    fn clean_cached_bytes(&self) -> u64 {
        self.clean_cached_blocks.len() as u64 * self.block_size
    }

    fn evict_clean_cache(&mut self) {
        while self.clean_cached_bytes() > self.max_dirty_bytes {
            let Some(index) = self.clean_cache_order.pop_front() else {
                break;
            };
            if !self.clean_cached_blocks.remove(&index) {
                continue;
            }
            if self.modified_blocks.contains(&index) {
                continue;
            }
            self.cached_blocks.remove(&index);
            self.loaded_store_blocks.remove(&index);
        }
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
        write_calls: Mutex<usize>,
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
            *self.write_calls.lock().unwrap() += 1;
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
            write_calls: Mutex::new(0),
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
            clean_cached_blocks: HashSet::new(),
            clean_cache_order: VecDeque::new(),
            max_dirty_bytes: 4096,
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
            write_calls: Mutex::new(0),
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
            clean_cached_blocks: HashSet::new(),
            clean_cache_order: VecDeque::new(),
            max_dirty_bytes: 4096,
        };

        block_on_ready(state.write_range(&[1; 4096], 4096)).unwrap();
        block_on_ready(state.write_range(&[2; 512], 4096)).unwrap();

        assert_eq!(state.cached_blocks.get(&1).unwrap()[..512], [2; 512]);
        assert_eq!(state.cached_blocks.get(&1).unwrap()[512..], [1; 3584]);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn write_from_flushes_when_dirty_bytes_reach_threshold() {
        let path = temp_base_image_path();
        fs::write(&path, [0_u8; 12288]).unwrap();
        let store = Arc::new(TestBlockStore {
            block_size: 4096,
            blocks: Mutex::new(HashMap::new()),
            write_calls: Mutex::new(0),
        });
        let storage = CowBlockStorage::open(&path, store.clone(), 8192).unwrap();

        block_on_ready(storage.write_from(&[1; 4096], 0)).unwrap();
        assert_eq!(*store.write_calls.lock().unwrap(), 0);

        block_on_ready(storage.write_from(&[2; 4096], 4096)).unwrap();
        assert_eq!(*store.write_calls.lock().unwrap(), 1);
        assert_eq!(store.blocks.lock().unwrap().len(), 2);
        assert_eq!(
            storage
                .state
                .lock()
                .expect("COW block storage lock poisoned")
                .cached_blocks
                .len(),
            2,
        );

        block_on_ready(storage.write_from(&[3; 4096], 8192)).unwrap();
        assert_eq!(*store.write_calls.lock().unwrap(), 1);

        block_on_ready(storage.flush()).unwrap();
        assert_eq!(*store.write_calls.lock().unwrap(), 2);
        let mut bytes = [0_u8; 4096];
        block_on_ready(storage.read_into(&mut bytes, 0)).unwrap();
        assert_eq!(bytes, [1; 4096]);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn flushed_blocks_stay_cached_until_clean_cache_limit() {
        let path = temp_base_image_path();
        fs::write(&path, [0_u8; 16384]).unwrap();
        let store = Arc::new(TestBlockStore {
            block_size: 4096,
            blocks: Mutex::new(HashMap::new()),
            write_calls: Mutex::new(0),
        });
        let storage = CowBlockStorage::open(&path, store.clone(), 8192).unwrap();

        block_on_ready(storage.write_from(&[1; 4096], 0)).unwrap();
        block_on_ready(storage.write_from(&[2; 4096], 4096)).unwrap();
        let mut bytes = [0_u8; 4096];
        block_on_ready(storage.read_into(&mut bytes, 0)).unwrap();
        assert_eq!(bytes, [1; 4096]);

        block_on_ready(storage.write_from(&[3; 4096], 8192)).unwrap();
        block_on_ready(storage.write_from(&[4; 4096], 12288)).unwrap();

        let state = storage
            .state
            .lock()
            .expect("COW block storage lock poisoned");
        assert_eq!(state.clean_cached_blocks.len(), 2);
        assert_eq!(state.cached_blocks.len(), 2);
        assert!(!state.cached_blocks.contains_key(&0));
        assert!(!state.cached_blocks.contains_key(&1));
        assert!(state.cached_blocks.contains_key(&2));
        assert!(state.cached_blocks.contains_key(&3));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn loaded_store_blocks_evict_clean_cache_over_limit() {
        let path = temp_base_image_path();
        fs::write(&path, [0_u8; 16384]).unwrap();
        let base = File::open(&path).unwrap();
        let store = Arc::new(TestBlockStore {
            block_size: 4096,
            blocks: Mutex::new(HashMap::from([
                (0, vec![1; 4096]),
                (1, vec![2; 4096]),
                (2, vec![3; 4096]),
                (3, vec![4; 4096]),
            ])),
            write_calls: Mutex::new(0),
        });
        let mut state = CowBlockStorageState {
            base: CowBlockBase::File(base),
            size: 16384,
            block_size: 4096,
            store,
            store_blocks: HashSet::from([0, 1, 2, 3]),
            loaded_store_blocks: HashSet::new(),
            cached_blocks: HashMap::new(),
            modified_blocks: HashSet::new(),
            clean_cached_blocks: HashSet::new(),
            clean_cache_order: VecDeque::new(),
            max_dirty_bytes: 4096,
        };

        state.load_store_blocks(0, 3).unwrap();

        assert_eq!(state.clean_cached_blocks.len(), 1);
        assert_eq!(state.cached_blocks.len(), 1);
        assert!(state.cached_blocks.contains_key(&3));
        assert_eq!(state.loaded_store_blocks, HashSet::from([3]));
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
