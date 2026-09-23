use std::{thread, time::Duration};

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
        Dechunker::default().receive(&chunk),
        Err(ReceiveError::UnsupportedVersion { tag: 0 })
    ));
}

#[test]
fn round_trip_out_of_order() {
    let data: Vec<_> = (0..CHUNK_DATA_SIZE * 65 + 17)
        .map(|index| index as u8)
        .collect();
    let chunks: Vec<_> = chunk_with_sequence(&data, 7).collect();
    let mut dechunker = Dechunker::default();
    let mut completed = None;

    for chunk in chunks.iter().rev() {
        completed = dechunker.receive(chunk).unwrap();
    }
    assert_eq!(completed, Some(data));
}

#[test]
fn two_records_can_arrive_out_of_order() {
    let old = vec![1; CHUNK_DATA_SIZE * 2];
    let new = vec![2; CHUNK_DATA_SIZE + 1];
    let old_chunks: Vec<_> = chunk_with_sequence(&old, u16::MAX).collect();
    let new_chunks: Vec<_> = chunk_with_sequence(&new, 0).collect();
    let mut dechunker = Dechunker::default();

    dechunker.receive(&old_chunks[0]).unwrap();
    dechunker.receive(&old_chunks[0]).unwrap();
    dechunker.receive(&new_chunks[1]).unwrap();
    assert_eq!(dechunker.receive(&old_chunks[1]).unwrap(), Some(old));
    assert_eq!(dechunker.receive(&new_chunks[0]).unwrap(), Some(new));
}

#[test]
fn inactive_records_do_not_block_a_restarted_sender() {
    let inactivity_timeout = Duration::from_millis(10);
    let old = vec![0; CHUNK_DATA_SIZE * 2];
    let first_old = chunk_with_sequence(&old, 20_000).next().unwrap();
    let second_old = chunk_with_sequence(&old, 20_001).next().unwrap();
    let new = [1];
    let new_chunk = chunk_with_sequence(&new, 0).next().unwrap();
    let mut dechunker = Dechunker::new(inactivity_timeout);

    dechunker.receive(&first_old).unwrap();
    dechunker.receive(&second_old).unwrap();
    assert!(matches!(
        dechunker.receive(&new_chunk),
        Err(ReceiveError::StaleSequence { .. })
    ));

    thread::sleep(inactivity_timeout);
    assert_eq!(dechunker.receive(&new_chunk).unwrap(), Some(new.to_vec()));
}

#[test]
fn rejects_truncated_chunk() {
    let chunk = chunk_with_sequence(&[0; CHUNK_DATA_SIZE], 0)
        .next()
        .unwrap();
    let mut dechunker = Dechunker::default();
    assert!(matches!(
        dechunker.receive(&chunk[..chunk.len() - 1]),
        Err(ReceiveError::ChunkTooSmall { .. })
    ));
}

#[test]
fn exact_chunk_boundary_terminates() {
    assert_eq!(
        chunk_with_sequence(&vec![0; CHUNK_DATA_SIZE * 2], 0).count(),
        2
    );
}
