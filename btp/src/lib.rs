use consts::APP_MTU;
use minicbor::encode::Write;
use rand::Rng;
use std::collections::HashMap;

mod tests;

pub struct Chunker<'a> {
    data: &'a [u8],
    total_chunks: usize,
    current_chunk: usize,
    message_id: u16,
}

struct SizedWriter {
    buffer: [u8; APP_MTU],
    pos: usize,
}

impl Write for SizedWriter {
    type Error = EndOfSlice;

    fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error> {
        if self.pos + buf.len() > APP_MTU {
            return Err(EndOfSlice);
        }
        self.buffer[self.pos..self.pos + buf.len()].copy_from_slice(buf);
        self.pos += buf.len();
        Ok(())
    }
}
/// An error indicating the end of a slice.
#[derive(Debug)]

pub struct EndOfSlice;

impl core::fmt::Display for EndOfSlice {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_str("end of slice")
    }
}

impl core::error::Error for EndOfSlice {}


pub fn chunk(data: &[u8]) -> Vec<[u8; APP_MTU]> {
    let message_id = rand::rng().random::<u16>();
    let current_chunk = 0;
    let total_chunks = 0;

    let chunks = vec![];

    loop {
        if current_chunk >= total_chunks {
            return chunks;
        }

        let mut encoder = minicbor::Encoder::new(SizedWriter {
            buffer: [0; APP_MTU],
            pos: 0,
        });

        // Encode chunk index (m of n) and data
        encoder
            .u16(message_id)
            .unwrap()
            .u32(current_chunk as u32)
            .unwrap()
            .u32(total_chunks as u32)
            .unwrap(); // m of n

        dbg!(encoder.writer().pos);

        let metadata_size = encoder.writer().pos;

        let remaining_data = APP_MTU - metadata_size;
        let chunk_size = std::cmp::min(remaining_data, APP_MTU);
        let chunk = &self.data[self.current_chunk * chunk_size..][..chunk_size];

        encoder.bytes(chunk).unwrap();

        self.current_chunk += 1;
        Some(encoder.into_writer().buffer)
    }


    Chunker {
        data,
        total_chunks: 0,
        current_chunk: 0,
        message_id,
    }
}

#[derive(Default)]
pub struct Dechunker {
    data: Vec<u8>,
    pub seen: u32,
    is_complete: bool,
    pub ooo_chunks: HashMap<u32, Vec<u8>>,
    pub m: u32,
    pub n: u32,
    pub id: u16,
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
    pub fn progress(&self) -> f32 {
        if self.n == 0 {
            0.0
        } else {
            self.seen.min(self.n) as f32 / self.n as f32
        }
    }
}

impl Dechunker {
    pub fn receive(&mut self, data: &[u8]) -> anyhow::Result<Option<&Vec<u8>>> {
        let mut decoder = minicbor::Decoder::new(data);

        let id = decoder.u16().map_err(|_| {
            self.clear();
            anyhow::anyhow!("Invalid ID")
        })?;

        let m = decoder.u32().map_err(|_| {
            self.clear();
            anyhow::anyhow!("Invalid m value")
        })?;

        if m == 0 {
            self.id = id;
        } else if self.id != id {
            return Ok(None);
        }

        let n = decoder.u32().map_err(|_| {
            self.clear();
            anyhow::anyhow!("Invalid n value")
        })?;

        if n == 0 {
            self.clear();
            return Err(anyhow::anyhow!("n cannot be zero"));
        }

        if m >= n {
            self.clear();
            return Err(anyhow::anyhow!("m must be less than n"));
        }

        self.m = m;
        self.n = n;

        // Decode chunk data
        let chunk_data = decoder.bytes().map_err(|_| {
            self.clear();
            anyhow::anyhow!("Invalid chunk data")
        })?;

        // Handle out-of-order chunks first
        if m != self.seen {
            self.ooo_chunks.insert(m, chunk_data.to_vec());

            // Try to process any in-order chunks we might have now
            while !self.ooo_chunks.is_empty() {
                if let Some(&next_m) = self.ooo_chunks.keys().min() {
                    if next_m == self.seen {
                        let data = self.ooo_chunks.remove(&next_m).unwrap();
                        self.data.extend(data);
                        self.seen += 1;
                    } else {
                        break;
                    }
                }
            }

            return Ok(None);
        }

        // Handle in-order chunk
        self.data.extend_from_slice(chunk_data);
        self.seen += 1;

        // Process any buffered OoO chunks that are now in-order
        while let Some(data) = self.ooo_chunks.remove(&self.seen) {
            self.data.extend(data);
            self.seen += 1;
        }

        // Check if transfer is complete
        if self.seen == self.n {
            self.is_complete = true;
            return Ok(Some(&self.data));
        }

        Ok(None)
    }
}
