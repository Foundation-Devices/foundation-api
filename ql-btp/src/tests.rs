use crate::{
    chunk_with_sequence, packet_version, Dechunker, ReceiveError, Version, CHUNK_DATA_SIZE,
};

#[test]
fn packet_version_uses_v1_padding_byte() {
    let mut chunk = chunk_with_sequence(&[1], 0).next().unwrap();
    assert_eq!(packet_version(&chunk), Some(Version::V2));

    chunk[7] = 0;
    assert_eq!(packet_version(&chunk), Some(Version::V1));
    assert!(matches!(
        Dechunker::new().receive(&chunk),
        Err(ReceiveError::UnsupportedVersion { tag: 0 })
    ));
}

#[test]
fn round_trip_out_of_order() {
    let data: Vec<_> = (0..CHUNK_DATA_SIZE * 65 + 17)
        .map(|index| index as u8)
        .collect();
    let chunks: Vec<_> = chunk_with_sequence(&data, 7).collect();
    let mut dechunker = Dechunker::new();
    let mut completed = None;

    for chunk in chunks.iter().rev() {
        completed = dechunker.receive(chunk).unwrap();
    }
    assert_eq!(completed, Some(data));
}

#[test]
fn newer_sequence_replaces_incomplete_record() {
    let old = vec![1; CHUNK_DATA_SIZE * 2];
    let new = vec![2; CHUNK_DATA_SIZE + 1];
    let old_chunks: Vec<_> = chunk_with_sequence(&old, u16::MAX).collect();
    let new_chunks: Vec<_> = chunk_with_sequence(&new, 0).collect();
    let mut dechunker = Dechunker::new();

    dechunker.receive(&old_chunks[0]).unwrap();
    dechunker.receive(&new_chunks[1]).unwrap();
    assert!(matches!(
        dechunker.receive(&old_chunks[1]),
        Err(ReceiveError::StaleSequence { .. })
    ));
    assert_eq!(dechunker.receive(&new_chunks[0]).unwrap(), Some(new));
}

#[test]
fn first_chunk_resets_sequence_after_sender_restart() {
    let old: Vec<_> = chunk_with_sequence(&vec![1; CHUNK_DATA_SIZE * 2], 20_000).collect();
    let new = vec![2; CHUNK_DATA_SIZE + 1];
    let new_chunks: Vec<_> = chunk_with_sequence(&new, 0).collect();
    let mut dechunker = Dechunker::new();

    dechunker.receive(&old[0]).unwrap();
    dechunker.receive(&new_chunks[0]).unwrap();
    assert_eq!(dechunker.receive(&new_chunks[1]).unwrap(), Some(new));
}

#[test]
fn rejects_truncated_chunk() {
    let chunk = chunk_with_sequence(&[0; CHUNK_DATA_SIZE], 0)
        .next()
        .unwrap();
    let mut dechunker = Dechunker::new();
    assert!(matches!(
        dechunker.receive(&chunk[..chunk.len() - 1]),
        Err(ReceiveError::ChunkTooSmall { .. })
    ));
}

#[test]
fn progress_counts_unique_chunks() {
    let data = vec![0; CHUNK_DATA_SIZE * 2];
    let chunks: Vec<_> = chunk_with_sequence(&data, 0).collect();
    let mut dechunker = Dechunker::new();

    dechunker.receive(&chunks[0]).unwrap();
    dechunker.receive(&chunks[0]).unwrap();
    assert_eq!(dechunker.progress(), 0.5);
    assert_eq!(dechunker.receive(&chunks[1]).unwrap(), Some(data));
}

#[test]
fn exact_chunk_boundary_terminates() {
    assert_eq!(
        chunk_with_sequence(&vec![0; CHUNK_DATA_SIZE * 2], 0).count(),
        2
    );
}
