use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::{Arc, Mutex};

use imago::Storage;
use imago::io_buffers::{IoVector, IoVectorMut};
use imago::storage::PreallocateMode;
use imago::storage::drivers::CommonStorageHelper;

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
    base: File,
    size: u64,
    block_size: u64,
    store: Arc<dyn CowBlockStore>,
    store_blocks: HashSet<u64>,
    loaded_store_blocks: HashSet<u64>,
    cached_blocks: HashMap<u64, Vec<u8>>,
    modified_blocks: HashSet<u64>,
}

impl CowBlockStorage {
    pub fn open(base_path: &Path, store: Arc<dyn CowBlockStore>) -> io::Result<Self> {
        let block_size = store.block_size();
        if block_size == 0 || block_size % 512 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "COW block size must be a positive multiple of 512 bytes",
            ));
        }

        let store_blocks = store.list_blocks()?;
        let base = File::open(base_path)?;
        let size = base.metadata()?.len();
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
            self.read_into(&mut bytes, offset)?;
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
            self.write_from(&bytes, offset)?;
            bufv = tail;
            offset = offset
                .checked_add(chunk_len as u64)
                .ok_or_else(|| io::Error::other("COW write offset overflow"))?;
        }
        Ok(())
    }

    async unsafe fn pure_write_zeroes(&self, offset: u64, length: u64) -> io::Result<()> {
        self.write_zeroes(offset, length)
    }

    async unsafe fn pure_write_allocated_zeroes(&self, offset: u64, length: u64) -> io::Result<()> {
        self.write_zeroes(offset, length)
    }

    async unsafe fn pure_discard(&self, offset: u64, length: u64) -> io::Result<()> {
        self.write_zeroes(offset, length)
    }

    async fn flush(&self) -> io::Result<()> {
        let (store, chunks) = {
            let mut state = self.state.lock().expect("COW block storage lock poisoned");
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
            state.modified_blocks.clear();
            (state.store.clone(), chunks)
        };
        if !chunks.is_empty() {
            store.write_blocks(chunks)?;
        }
        store.flush()
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
    fn read_into(&self, output: &mut [u8], offset: u64) -> io::Result<()> {
        let mut state = self.state.lock().expect("COW block storage lock poisoned");
        if offset >= state.size {
            output.fill(0);
            return Ok(());
        }

        let readable = output.len().min((state.size - offset) as usize);
        state.base.seek(SeekFrom::Start(offset))?;
        state.base.read_exact(&mut output[..readable])?;
        if readable < output.len() {
            output[readable..].fill(0);
        }
        state.overlay_range(output, offset)
    }

    fn write_from(&self, input: &[u8], offset: u64) -> io::Result<()> {
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
        state.write_range(input, offset)
    }

    fn write_zeroes(&self, offset: u64, length: u64) -> io::Result<()> {
        const ZERO_CHUNK_SIZE: usize = 1024 * 1024;
        let mut remaining = length;
        let mut next_offset = offset;
        let zeroes = vec![0; ZERO_CHUNK_SIZE];
        while remaining > 0 {
            let chunk_len = remaining.min(ZERO_CHUNK_SIZE as u64) as usize;
            self.write_from(&zeroes[..chunk_len], next_offset)?;
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

    fn write_range(&mut self, input: &[u8], offset: u64) -> io::Result<()> {
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
                self.base.seek(SeekFrom::Start(block_start))?;
                let bytes_read = self.base.read(&mut block)?;
                if bytes_read < block.len() {
                    block[bytes_read..].fill(0);
                }
                self.cached_blocks.insert(block_index, block);
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
                    || self.loaded_store_blocks.contains(&block))
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
            {
                block += 1;
            }
            let count = block - start;
            for (index, data) in self.store.read_blocks(start, count)? {
                if data.len() > self.block_size as usize {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "COW block store returned a chunk larger than block size",
                    ));
                }
                let mut block = vec![0; self.block_size as usize];
                block[..data.len()].copy_from_slice(&data);
                self.cached_blocks.insert(index, block);
            }
            self.loaded_store_blocks.extend(start..start + count);
        }
        Ok(())
    }
}
