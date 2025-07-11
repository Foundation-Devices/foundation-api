use crate::{chunk, Dechunker, APP_MTU, CHUNK_DATA_SIZE};

#[test]
fn end_to_end() {
    let data = b"
        This is some example data to be chunked.This is some example data to be chunked.This is some example data to be chunked.
        This is some example data to be chunked.This is some example data to be chunked.This is some example data to be chunked.
        This is some example data to be chunked.This is some example data to be chunked.This is some example data to be chunked.
        This is some example data to be chunked.This is some example data to be chunked.This is some example data to be chunked.
        ".to_vec();

    let chunked_data: Vec<[u8; APP_MTU]> = chunk(&data).collect();

    assert_eq!(chunked_data.len(), 3);

    let mut unchunker = Dechunker::new();

    for chunk in chunked_data {
        unchunker
            .receive(chunk.as_ref())
            .expect("Failed to receive chunk");
    }

    assert_eq!(unchunker.data(), Some(data));
    assert!(unchunker.is_complete());
}

#[test]
fn end_to_end_ooo() {
    let data = vec![0u8; 100000];

    let mut chunked_data: Vec<[u8; APP_MTU]> = chunk(&data).collect();

    chunked_data.swap(0, 2);
    chunked_data.swap(4, 3);

    let mut dechunker = Dechunker::new();

    for chunk in chunked_data.iter() {
        dechunker
            .receive(chunk.as_ref())
            .expect("Failed to receive chunk");
    }

    assert_eq!(dechunker.data(), Some(data));
}

#[test]
fn test_single_chunk() {
    let data = b"Small data".to_vec();
    let chunks: Vec<_> = chunk(&data).collect();

    assert_eq!(chunks.len(), 1);

    let mut dechunker = Dechunker::new();
    dechunker.receive(&chunks[0]).unwrap();

    assert_eq!(dechunker.data(), Some(data));
    assert!(dechunker.is_complete());
}

#[test]
fn test_empty_data() {
    let data = b"";
    let chunks: Vec<_> = chunk(data).collect();
    assert_eq!(chunks.len(), 0, "Empty data should produce no chunks");
}

#[test]
fn test_exact_chunk_boundary() {
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
fn test_different_message_ids() {
    let data1 = b"Message 1".to_vec();
    let data2 = b"Message 2".to_vec();

    let chunks1: Vec<_> = chunk(&data1).collect();
    let chunks2: Vec<_> = chunk(&data2).collect();

    let mut dechunker1 = Dechunker::new();
    let mut dechunker2 = Dechunker::new();

    dechunker1.receive(&chunks1[0]).unwrap();

    let result = dechunker1.receive(&chunks2[0]);
    assert!(
        matches!(result, Err(crate::DecodeError::WrongMessageId { .. })),
        "Chunk from different message should be rejected"
    );

    dechunker2.receive(&chunks2[0]).unwrap();
    assert_eq!(dechunker2.data(), Some(data2));
}

#[test]
fn test_progress_tracking() {
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
fn test_duplicate_chunks() {
    let data = b"Test duplicate handling".to_vec();
    let chunks: Vec<_> = chunk(&data).collect();

    let mut dechunker = Dechunker::new();

    dechunker.receive(&chunks[0]).unwrap();
    dechunker.receive(&chunks[0]).unwrap();

    dechunker.receive(&chunks[0]).unwrap();
    assert_eq!(
        dechunker.data(),
        Some(data),
        "Data should be correctly reassembled despite duplicates"
    );
}

#[test]
fn test_missing_middle_chunk() {
    let data = vec![1u8; 1000];
    let chunks: Vec<_> = chunk(&data).collect();

    if chunks.len() < 3 {
        return;
    }

    let mut dechunker = Dechunker::new();

    let middle = chunks.len() / 2;

    for (i, chunk) in chunks.iter().enumerate() {
        if i != middle {
            dechunker.receive(chunk).unwrap();
        }
    }

    assert!(
        dechunker.data().is_none(),
        "Message should not complete with middle chunk still missing"
    );

    dechunker.receive(&chunks[middle]).unwrap();

    assert_eq!(dechunker.data(), Some(data));
    assert!(dechunker.is_complete());
}

#[test]
fn test_data_with_zeros() {
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
fn test_reverse_order_decoding() {
    let data = b"
        This is some example data to be chunked.This is some example data to be chunked.This is some example data to be chunked.
        This is some example data to be chunked.This is some example data to be chunked.This is some example data to be chunked.
        This is some example data to be chunked.This is some example data to be chunked.This is some example data to be chunked.
        This is some example data to be chunked.This is some example data to be chunked.This is some example data to be chunked.
        ".to_vec();
    let chunks: Vec<_> = chunk(&data).collect();

    let mut dechunker = Dechunker::new();

    for chunk in chunks.iter().rev() {
        dechunker.receive(chunk).unwrap();
    }

    assert!(dechunker.is_complete(), "Dechunker should be complete");
    assert_eq!(
        dechunker.data(),
        Some(data),
        "Final data should match original"
    );
}
