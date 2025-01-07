use consts::APP_MTU;

const CHUNK_SIZE: usize = APP_MTU - 5;

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
            .array(2)
            .unwrap()
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

pub struct Unchunker {
    data: Vec<u8>,
    seen: u32,
    is_complete: bool,
}

impl Unchunker {
    pub fn new() -> Self {
        Self {
            data: Vec::new(),
            seen: 0,
            is_complete: false,
        }
    }

    pub fn is_complete(&self) -> bool {
        self.is_complete
    }

    pub fn data(&self) -> &Vec<u8> {
        &self.data
    }
}

impl Unchunker {
    pub fn receive(&mut self, data: &Vec<u8>) -> anyhow::Result<Option<&Vec<u8>>> {
        let mut decoder = minicbor::Decoder::new(data);
        let array_len = decoder.array()?.unwrap();
        if array_len != 2 {
            return Err(anyhow::anyhow!("Invalid array length"));
        }

        let m = decoder.u32()?;
        let n = decoder.u32()?;

        if n == 0 {
            return Err(anyhow::anyhow!("Invalid n value"));
        }

        if (m > n) || (m > self.seen) {
            return Err(anyhow::anyhow!("Invalid m value"));
        }

        self.seen += 1;

        let chunk_data = decoder.bytes()?;
        self.data.extend_from_slice(chunk_data);

        if self.seen == n {
            self.is_complete = true;
            return Ok(Some(&self.data));
        };

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn end_to_end() {
        // Example data
        let data = b"This is some example data to be chunked using minicbor.This is some example data to be chunked using minicbor.This is some example data to be chunked using minicbor.This is some example data to be chunked using minicbor.This is some example data to be chunked using minicbor.This is some example data to be chunked using minicbor.This is some example data to be chunked using minicbor.This is some example data to be chunked using minicbor.This is some example data to be chunked using minicbor.";

        // Chunk the data
        let chunked_data: Vec<[u8; APP_MTU]> = chunk(data).collect();

        assert_eq!(chunked_data.len(), 3);

        // Unchunk the data
        let mut unchunker = Unchunker::new();

        for chunk in chunked_data {
            if let Ok(Some(unchunked_data)) = unchunker.receive(&chunk.to_vec()) {
                assert!(data.eq(unchunked_data.as_slice()));
            }
        }
    }
}
