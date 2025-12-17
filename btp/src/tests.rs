use rand::{seq::SliceRandom, Rng, RngCore};

use crate::{
    chunk, Chunk, Dechunker, DecodeError, MasterDechunker, ReceiveError, APP_MTU, CHUNK_DATA_SIZE,
    HEADER_SIZE,
};

static TEST_STR: &[u8]= b"
This is some example data to be chunked.This is some example data to be chunked.This is some example data to be chunked.
This is some example data to be chunked.This is some example data to be chunked.This is some example data to be chunked.
This is some example data to be chunked.This is some example data to be chunked.This is some example data to be chunked.
This is some example data to be chunked.This is some example data to be chunked.This is some example data to be chunked.
";

#[test]
fn end_to_end() {
    let chunked_data: Vec<[u8; APP_MTU]> = chunk(TEST_STR).collect();

    assert_eq!(chunked_data.len(), 3);

    let mut unchunker = Dechunker::new();

    for chunk in chunked_data {
        unchunker
            .receive(chunk.as_ref())
            .expect("Failed to receive chunk");
    }

    assert_eq!(unchunker.data(), Some(TEST_STR.to_vec()));
    assert!(unchunker.is_complete());
}

#[test]
fn single_chunk() {
    let data = b"Small data".to_vec();
    let chunks: Vec<_> = chunk(&data).collect();

    assert_eq!(chunks.len(), 1);

    let mut dechunker = Dechunker::new();
    dechunker.receive(&chunks[0]).unwrap();

    assert_eq!(dechunker.data(), Some(data));
    assert!(dechunker.is_complete());
}

#[test]
fn empty_data() {
    let data = b"";
    let chunks: Vec<_> = chunk(data).collect();
    assert_eq!(chunks.len(), 0, "Empty data should produce no chunks");
}

#[test]
fn exact_chunk_boundary() {
    let data = vec![42u8; CHUNK_DATA_SIZE * 3];

    let chunks: Vec<_> = chunk(&data).collect();
    assert_eq!(
        chunks.len(),
        3,
        "Data exactly filling 3 chunks should produce 3 chunks"
    );

    let mut dechunker = Dechunker::new();
    for (i, chunk) in chunks.iter().enumerate() {
        dechunker.receive(chunk).unwrap();
        if i == chunks.len() - 1 {
            assert_eq!(
                dechunker.data().as_ref(),
                Some(&data),
                "last chunk should complete the message"
            );
        }
    }
    assert_eq!(dechunker.data(), Some(data))
}

#[test]
fn different_message_ids() {
    let data1 = b"Message 1".to_vec();
    let data2 = b"Message 2".to_vec();

    let chunks1: Vec<_> = chunk(&data1).collect();
    let chunks2: Vec<_> = chunk(&data2).collect();

    let mut dechunker1 = Dechunker::new();
    dechunker1.receive(&chunks1[0]).unwrap();

    let result = dechunker1.receive(&chunks2[0]);
    assert!(
        matches!(
            result,
            Err(crate::ReceiveError::MessageId(crate::MessageIdError { .. }))
        ),
        "Chunk from different message should be rejected"
    );
}

#[test]
fn progress_tracking() {
    let data = vec![1u8; 10000];
    let chunks: Vec<_> = chunk(&data).collect();

    let mut dechunker = Dechunker::new();

    assert_eq!(dechunker.progress(), 0.0, "Initial progress should be 0");

    let mut last_progress = 0.0;
    for (i, chunk) in chunks.iter().enumerate() {
        dechunker.receive(chunk).unwrap();

        let current_progress = dechunker.progress();

        assert!(
            current_progress >= last_progress,
            "Progress should never decrease"
        );

        if i == chunks.len() - 1 {
            assert!(
                (current_progress - 1.0).abs() < 0.01,
                "Progress should be 1.0 when all chunks received"
            );
        }

        last_progress = current_progress;
    }

    assert_eq!(dechunker.data(), Some(data));
}

#[test]
fn data_with_zeros() {
    let mut data = vec![0u8; 500];
    data[100] = 1;
    data[200] = 2;
    data[300] = 3;
    data[400] = 4;

    let chunks: Vec<_> = chunk(&data).collect();
    let mut dechunker = Dechunker::new();

    for chunk in chunks {
        dechunker.receive(&chunk).unwrap();
    }

    assert_eq!(
        dechunker.data(),
        Some(data),
        "Dechunker should complete successfully with zero-containing data"
    );
}

#[test]
fn chunk_decode_and_insert() {
    use crate::Chunk;

    let data = b"Test data for decode and push";
    let chunks: Vec<_> = chunk(data).collect();

    let mut dechunker = Dechunker::new();

    for raw_chunk in &chunks {
        let decoded = Chunk::decode(raw_chunk).unwrap();
        dechunker.insert_chunk(decoded).unwrap();
    }

    assert_eq!(dechunker.data(), Some(data.to_vec()));
}

#[test]
fn chunk_decode_errors() {
    let small_data = vec![0u8; HEADER_SIZE - 1];
    let result = Chunk::decode(&small_data);
    assert!(matches!(result, Err(DecodeError::HeaderTooSmall)));
}

#[test]
fn chunk_too_small() {
    let header = crate::Header::new(1234, 0, 1, 100);
    let mut raw_chunk = vec![0u8; HEADER_SIZE + 5];
    raw_chunk[..HEADER_SIZE].copy_from_slice(header.as_bytes());

    let result = Chunk::decode(&raw_chunk);
    assert!(
        matches!(
            result,
            Err(DecodeError::ChunkTooSmall {
                expected: 100,
                actual: 5
            })
        ),
        "should fail if actual data is less than header claims"
    );
}

#[test]
fn chunk_too_large() {
    let header = crate::Header::new(1234, 0, 1, 255);
    let mut raw_chunk = vec![0u8; HEADER_SIZE + 255];
    raw_chunk[..HEADER_SIZE].copy_from_slice(header.as_bytes());

    let result = Chunk::decode(&raw_chunk);
    assert!(
        matches!(result, Err(DecodeError::ChunkTooLarge)),
        "should fail when data_len exceeds maximum chunk size"
    );
}

#[test]
fn chunk_decode_invalid_index() {
    use crate::{Chunk, DecodeError, HEADER_SIZE};

    let header = crate::Header::new(1234, 10, 1, 5);
    let mut raw_chunk = vec![0u8; HEADER_SIZE + 5];
    raw_chunk[..HEADER_SIZE].copy_from_slice(header.as_bytes());

    let result = Chunk::decode(&raw_chunk);
    assert!(
        matches!(
            result,
            Err(DecodeError::InvalidChunkIndex {
                index: 10,
                total_chunks: 1
            })
        ),
        "invalid index"
    );
}

#[test]
fn insert_chunk_wrong_message_id() {
    let data1 = b"First message";
    let data2 = b"Second message";

    let chunks1: Vec<_> = chunk(data1).collect();
    let chunks2: Vec<_> = chunk(data2).collect();

    let mut dechunker = Dechunker::new();

    let chunk1 = Chunk::decode(&chunks1[0]).unwrap();
    dechunker.insert_chunk(chunk1).unwrap();

    let chunk2 = Chunk::decode(&chunks2[0]).unwrap();
    let result = dechunker.insert_chunk(chunk2);

    assert!(
        matches!(result, Err(ReceiveError::MessageId(_))),
        "message id mismatch"
    );
}

#[test]
fn master_dechunker_basic() {
    let data = b"Test data for master dechunker";
    let chunks: Vec<_> = chunk(data).collect();

    let mut master = MasterDechunker::<10>::default();

    for (i, chunk) in chunks.iter().enumerate() {
        let decoded = Chunk::decode(chunk).unwrap();
        let result = master.insert_chunk(decoded);

        if i == chunks.len() - 1 {
            assert_eq!(
                result,
                Some(data.to_vec()),
                "Last chunk should return completed data"
            );
        } else {
            assert_eq!(result, None, "Intermediate chunks should return None");
        }
    }
}

#[test]
fn master_dechunker_multiple_messages() {
    let data1 = b"First message data";
    let data2 = b"Second message data";
    let data3 = b"Third message data";

    let chunks1: Vec<_> = chunk(data1).collect();
    let chunks2: Vec<_> = chunk(data2).collect();
    let chunks3: Vec<_> = chunk(data3).collect();

    let mut master = MasterDechunker::<3>::default();

    let mut all_chunks = Vec::new();
    for i in 0..chunks1.len().max(chunks2.len()).max(chunks3.len()) {
        if i < chunks1.len() {
            all_chunks.push((1, &chunks1[i]));
        }
        if i < chunks2.len() {
            all_chunks.push((2, &chunks2[i]));
        }
        if i < chunks3.len() {
            all_chunks.push((3, &chunks3[i]));
        }
    }

    let mut completed = Vec::new();

    for (msg_id, chunk) in all_chunks {
        let decoded = Chunk::decode(chunk).unwrap();
        if let Some(data) = master.insert_chunk(decoded) {
            completed.push((msg_id, data));
        }
    }

    assert_eq!(completed.len(), 3, "All three messages should complete");

    for (msg_id, data) in completed {
        match msg_id {
            1 => assert_eq!(data, data1.to_vec(), "Message 1 data should match"),
            2 => assert_eq!(data, data2.to_vec(), "Message 2 data should match"),
            3 => assert_eq!(data, data3.to_vec(), "Message 3 data should match"),
            _ => panic!("Unexpected message ID: {msg_id}"),
        }
    }
}

#[test]
fn master_dechunker_lru_eviction() {
    let mut master = MasterDechunker::<2>::default();

    let data1 = vec![1u8; 1000];
    let data2 = vec![2u8; 1000];
    let data3 = vec![3u8; 1000];

    let chunks1: Vec<_> = chunk(&data1).collect();
    let chunks2: Vec<_> = chunk(&data2).collect();
    let chunks3: Vec<_> = chunk(&data3).collect();

    assert!(
        chunks1.len() > 1,
        "Message 1 should require multiple chunks"
    );
    assert!(
        chunks2.len() > 1,
        "Message 2 should require multiple chunks"
    );
    assert!(
        chunks3.len() > 1,
        "Message 3 should require multiple chunks"
    );

    let decoded1_0 = Chunk::decode(&chunks1[0]).unwrap();
    let decoded2_0 = Chunk::decode(&chunks2[0]).unwrap();
    let decoded2_1 = Chunk::decode(&chunks2[1]).unwrap();
    let decoded3_0 = Chunk::decode(&chunks3[0]).unwrap();

    master.insert_chunk(decoded1_0);
    master.insert_chunk(decoded2_0);

    master.insert_chunk(decoded2_1);

    let result = master.insert_chunk(decoded3_0);
    assert_eq!(
        result, None,
        "Third message should succeed by evicting LRU slot"
    );

    let decoded1_0_again = Chunk::decode(&chunks1[0]).unwrap();
    let result = master.insert_chunk(decoded1_0_again);
    assert_eq!(
        result, None,
        "Message 1 should start fresh after being evicted"
    );
}

#[test]
fn master_dechunker_single_chunk_message() {
    let data = b"Small";
    let chunks: Vec<_> = chunk(data).collect();
    assert_eq!(chunks.len(), 1, "Small message should be single chunk");

    let mut master = MasterDechunker::<10>::default();
    let decoded = Chunk::decode(&chunks[0]).unwrap();
    let result = master.insert_chunk(decoded);

    assert_eq!(
        result,
        Some(data.to_vec()),
        "Single chunk message should complete immediately"
    );
}
