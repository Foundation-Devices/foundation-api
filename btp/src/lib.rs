use consts::APP_MTU;
use std::collections::HashMap;

mod tests;

// TODO: is it possible to make this dynamic?
const CHUNK_SIZE: usize = APP_MTU - 6;

pub struct Chunker<'a> {
    data: &'a [u8],
    total_chunks: usize,
    current_chunk: usize,
}

impl<'a> Iterator for Chunker<'a> {
    type Item = [u8; APP_MTU];

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_chunk >= self.total_chunks {
            return None;
        }

        let remaining_data = self.data.len() - self.current_chunk * CHUNK_SIZE;
        let chunk_size = std::cmp::min(remaining_data, CHUNK_SIZE);
        let chunk = &self.data[self.current_chunk * CHUNK_SIZE..][..chunk_size];

        let mut buffer = [0u8; APP_MTU];
        let mut encoder = minicbor::Encoder::new(&mut buffer[..]);

        // Encode chunk index (m of n) and data
        encoder
            .u32(self.current_chunk as u32)
            .unwrap()
            .u32(self.total_chunks as u32)
            .unwrap(); // m of n
        encoder.bytes(chunk).unwrap();

        self.current_chunk += 1;
        Some(buffer)
    }
}

pub fn chunk(data: &[u8]) -> Chunker<'_> {
    let total_chunks = (data.len() as f64 / CHUNK_SIZE as f64).ceil() as usize;
    Chunker {
        data,
        total_chunks,
        current_chunk: 0,
    }
}

#[derive(Default)]
pub struct Dechunker {
    data: Vec<u8>,
    seen: u32,
    is_complete: bool,
    ooo_chunks: HashMap<u32, Vec<u8>>,
}

impl Dechunker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_complete(&self) -> bool {
        self.is_complete
    }

    pub fn data(&self) -> &Vec<u8> {
        &self.data
    }

    pub fn clear(&mut self) {
        self.ooo_chunks.clear();
        self.data.clear();
        self.seen = 0;
        self.is_complete = false;
    }
}

impl Dechunker {
    pub fn receive(&mut self, data: &Vec<u8>) -> anyhow::Result<Option<&Vec<u8>>> {
        let mut decoder = minicbor::Decoder::new(data);

        let m = decoder.u32().map_err(|_| {
            self.clear();
            anyhow::anyhow!("Invalid m value")
        })?;

        let n = decoder.u32().map_err(|_| {
            self.clear();
            anyhow::anyhow!("Invalid n value")
        })?;

        if n == 0 {
            self.clear();
            return Err(anyhow::anyhow!("n cannot be zero"));
        }

        if m > n {
            self.clear();
            return Err(anyhow::anyhow!("m cannot be greater than n"));
        }

        while !self.ooo_chunks.is_empty() {
            let first_ooo = *self.ooo_chunks.keys().min().unwrap();
            if m > first_ooo {
                let chunk_data = self.ooo_chunks.remove(&first_ooo).unwrap();
                self.data.extend(chunk_data);
            } else {
                break;
            }
        }

        // Store chunk if it's out of order
        if m != self.seen {
            let chunk_data = decoder.bytes().map_err(|_| {
                self.clear();
                anyhow::anyhow!("Cannot parse OoO chunk data")
            })?;
            self.ooo_chunks.insert(m, chunk_data.to_vec());
            self.seen += 1;
            return Ok(None);
        }

        self.seen += 1;

        let chunk_data = decoder.bytes().map_err(|_| {
            self.clear();
            anyhow::anyhow!("Invalid chunk data")
        })?;

        self.data.extend_from_slice(chunk_data);

        if self.seen == n {
            self.is_complete = true;
            return Ok(Some(&self.data));
        };

        Ok(None)
    }
}
