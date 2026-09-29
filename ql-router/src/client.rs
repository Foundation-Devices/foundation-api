use std::io;

use ql_codec::Decode;
use ql_wire::{
    generate_identity, HandshakeId, IkHandshake, PeerBundle, QlHandshakeRecord, QlIdentity,
    RecordHeader, RecordType, RouteHeader, SessionKey, SoftwareCrypto, TransportParams,
};
use tokio::net::{
    tcp::{OwnedReadHalf, OwnedWriteHalf},
    TcpStream, ToSocketAddrs,
};

use crate::{
    invalid_data,
    protocol::{self, AttachChallenge, AttachRecord, PacketKind},
};

pub struct Receiver {
    tcp: OwnedReadHalf,
    key: SessionKey,
    counter: u64,
}

pub struct Sender {
    tcp: OwnedWriteHalf,
    key: SessionKey,
    counter: u64,
    buffer: Vec<u8>,
}

pub async fn connect(
    address: impl ToSocketAddrs,
    router: &PeerBundle,
) -> io::Result<(Receiver, Sender)> {
    router.validate(&SoftwareCrypto).map_err(invalid_data)?;
    let mut tcp = TcpStream::connect(address).await?;
    tcp.set_nodelay(true)?;

    let identity = generate_identity(&SoftwareCrypto, "QL router transport");
    let route = RouteHeader {
        sender: identity.qid,
        recipient: router.qid,
    };
    let mut handshake = IkHandshake::new_ik_initiator(
        &SoftwareCrypto,
        identity,
        router.clone(),
        TransportParams::default(),
    );
    let mut random = [0; 4];
    ql_wire::QlRandom::fill_random_bytes(&SoftwareCrypto, &mut random);
    let handshake_id = HandshakeId::decode_bytes(random.as_slice()).unwrap();
    let request = ql_wire::encode_record_vec(
        RecordHeader::new(route, RecordType::Handshake),
        &QlHandshakeRecord::Ik1(
            handshake
                .write_1(&SoftwareCrypto, handshake_id)
                .map_err(invalid_data)?,
        ),
    );
    protocol::write_frame(&mut tcp, &request).await?;

    let response = protocol::read_frame(&mut tcp)
        .await?
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "router disconnected"))?;
    let protocol::TransportResponse {
        header,
        handshake: response,
    } = protocol::TransportResponse::decode_bytes(response.payload()).map_err(invalid_data)?;
    let QlHandshakeRecord::Ik2(response) = response else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected transport handshake record",
        ));
    };
    handshake
        .read_2(&SoftwareCrypto, header.route, &response)
        .map_err(invalid_data)?;
    let finalized = handshake.finalize(&SoftwareCrypto).map_err(invalid_data)?;
    if finalized.remote_bundle != *router {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "transport peer does not match router",
        ));
    }
    let tx_key = finalized.tx_key;
    let rx_key = finalized.rx_key;

    let confirmation =
        protocol::seal_packet(&SoftwareCrypto, &tx_key, PacketKind::Confirm, 0, &[])?;
    protocol::write_packet(&mut tcp, &confirmation).await?;

    let (tcp, writer) = tcp.into_split();
    Ok((
        Receiver {
            tcp,
            key: rx_key,
            counter: 0,
        },
        Sender {
            tcp: writer,
            key: tx_key,
            counter: 1,
            buffer: Vec::new(),
        },
    ))
}

pub async fn receive(receiver: &mut Receiver) -> io::Result<Option<Vec<u8>>> {
    let Some((kind, payload)) = receive_packet(receiver).await? else {
        return Ok(None);
    };
    match kind {
        PacketKind::Record => Ok(Some(payload)),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected router packet",
        )),
    }
}

pub async fn receive_packet(receiver: &mut Receiver) -> io::Result<Option<(PacketKind, Vec<u8>)>> {
    let Receiver { tcp, key, counter } = receiver;
    let Some(frame) = protocol::read_frame(tcp).await? else {
        return Ok(None);
    };
    let nonce = protocol::take_counter(counter)
        .ok_or_else(|| io::Error::other("nonce counter exhausted"))?;
    Ok(Some(protocol::open_packet_owned(
        &SoftwareCrypto,
        key,
        nonce,
        frame,
    )?))
}

pub async fn send(sender: &mut Sender, record: &[u8]) -> io::Result<()> {
    send_packet(sender, PacketKind::Record, record).await
}

pub async fn send_attach(sender: &mut Sender, handshake: &[u8]) -> io::Result<()> {
    send_packet(sender, PacketKind::Attach, handshake).await
}

pub async fn attach(
    receiver: &mut Receiver,
    sender: &mut Sender,
    identity: &QlIdentity,
    router: &PeerBundle,
) -> io::Result<()> {
    let route = RouteHeader {
        sender: identity.qid,
        recipient: router.qid,
    };
    let mut handshake = IkHandshake::new_ik_initiator(
        &SoftwareCrypto,
        identity,
        router.clone(),
        TransportParams::default(),
    );
    let mut random = [0; 4];
    ql_wire::QlRandom::fill_random_bytes(&SoftwareCrypto, &mut random);
    let handshake_id = HandshakeId::decode_bytes(random.as_slice()).unwrap();
    let request = ql_wire::encode_record_vec(
        RecordHeader::new(route, RecordType::Handshake),
        &AttachRecord::Initiate(
            handshake
                .write_1(&SoftwareCrypto, handshake_id)
                .map_err(invalid_data)?,
        ),
    );
    send_attach(sender, &request).await?;

    let (kind, response) = receive_packet(receiver)
        .await?
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "router disconnected"))?;
    if kind != PacketKind::Attach {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected router packet",
        ));
    }
    let (header, response) = protocol::decode_attach(&response)?;
    let AttachRecord::Challenge(AttachChallenge {
        handshake: response,
        cookie,
    }) = response
    else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected attachment handshake record",
        ));
    };
    handshake
        .read_2(&SoftwareCrypto, header.route, &response)
        .map_err(invalid_data)?;
    let finalized = handshake.finalize(&SoftwareCrypto).map_err(invalid_data)?;
    if finalized.remote_bundle != *router {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "attachment peer does not match router",
        ));
    }
    let confirmation = protocol::confirm_cookie(&SoftwareCrypto, &finalized.tx_key, cookie);
    let confirmation = ql_wire::encode_record_vec(
        RecordHeader::new(route, RecordType::Handshake),
        &AttachRecord::Confirm(confirmation),
    );
    send_attach(sender, &confirmation).await
}

async fn send_packet(sender: &mut Sender, kind: PacketKind, payload: &[u8]) -> io::Result<()> {
    let nonce = protocol::take_counter(&mut sender.counter)
        .ok_or_else(|| io::Error::other("nonce counter exhausted"))?;
    protocol::seal_packet_into(
        &SoftwareCrypto,
        &mut sender.buffer,
        &sender.key,
        kind,
        nonce,
        payload,
    )?;
    protocol::write_packet(&mut sender.tcp, &sender.buffer).await
}
