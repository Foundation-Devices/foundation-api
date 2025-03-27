#[cfg(test)]
mod tests {
    use crate::{chunk, APP_MTU, Dechunker};
    #[test]
    fn end_to_end() {
        // Example data
        let data = b"This is some example data to be chunked using minicbor.This is some example data to be chunked using minicbor.This is some example data to be chunked using minicbor.This is some example data to be chunked using minicbor.This is some example data to be chunked using minicbor.This is some example data to be chunked using minicbor.This is some example data to be chunked using minicbor.This is some example data to be chunked using minicbor.This is some example data to be chunked using minicbor.";

        // Chunk the data
        let chunked_data: Vec<[u8; APP_MTU]> = chunk(data).collect();

        assert_eq!(chunked_data.len(), 3);

        // Unchunk the data
        let mut unchunker = Dechunker::new();

        for chunk in chunked_data {
            unchunker
                .receive(&chunk.to_vec())
                .expect("TODO: panic message");
            if unchunker.is_complete() {
                assert!(data.eq(unchunker.data().as_slice()));
            }
        }
    }

    #[test]
    fn end_to_end_ooo() {
        // Example data
        let data = b"This is some example data to be chunked using minicbor.This is some example data to be chunked using minicbor.This is some example data to be chunked using minicbor.This is some example data to be chunked using minicbor.This is some example data to be chunked using minicbor.This is some example data to be chunked using minicbor.This is some example data to be chunked using minicbor.This is some example data to be chunked using minicbor.This is some example data to be chunked using minicbor.This is some example data to be chunked using minicbor.This is some example data to be chunked using minicbor.This is some example data to be chunked using minicbor.This is some example data to be chunked using minicbor.This is some example data to be chunked using minicbor.This is some example data to be chunked using minicbor.This is some example data to be chunked using minicbor.This is some example data to be chunked using minicbor.This is some example data to be chunked using minicbor.";

        // Chunk the data
        let mut chunked_data: Vec<[u8; APP_MTU]> = chunk(data).collect();

        // Shuffle every other to simulate them being received out of order
        chunked_data.swap(0, 2);

        chunked_data.swap(4, 3);

        // Unchunk the data
        let mut dechunker = Dechunker::new();

        for chunk in chunked_data {
            dechunker
                .receive(&chunk.to_vec())
                .expect("error receiving chunk");
            if dechunker.is_complete() {
                assert!(data.eq(dechunker.data().as_slice()));
            }
        }
    }
}