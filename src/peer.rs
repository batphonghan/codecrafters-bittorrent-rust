use crate::meta::{self, MetaInfo};
use serde::{Deserialize, Serialize};
pub struct HandshakeMessage {
    bytes: Vec<u8>,
}

// 1 + 19 + 8 + 20 + 20 => 68
impl From<MetaInfo> for HandshakeMessage {
    fn from(meta: meta::MetaInfo) -> HandshakeMessage {
        let mut bytes = Vec::with_capacity(68);

        let length: u8 = 19;
        let b_byte: [u8; 1] = length.to_be_bytes();
        bytes.extend(b_byte);

        bytes.extend(b"BitTorrent protocol");

        let reserved: [u8; 8] = [0; 8];
        bytes.extend(reserved);

        let info_hash = meta.info_hash_byte();
        bytes.extend(info_hash);

        bytes.extend(b"00112233445566778899");

        assert_eq!(bytes.len(), 68);

        HandshakeMessage { bytes }
    }
}

#[derive(Debug)]
pub enum PeerMessageType {
    Choke,
    Unchoke,
    Interested,
    NotInterest,
    Have,
    Bitfield,
    Request,
    Piece,
    Cancel,
    Undefine { b: u8 },
}

impl PeerMessageType {
    pub fn to_byte(&self) -> u8 {
        match self {
            PeerMessageType::Choke => 0,
            PeerMessageType::Unchoke => 1,
            PeerMessageType::Interested => 2,
            PeerMessageType::NotInterest => 3,
            PeerMessageType::Bitfield => 5,
            PeerMessageType::Request => 6,
            PeerMessageType::Piece => 7,
            _ => panic!("Undefine bytes {:?}", self),
        }
    }

    pub fn from_byte(b: u8) -> Self {
        match b {
            0 => PeerMessageType::Choke {},
            1 => PeerMessageType::Unchoke {},
            2 => PeerMessageType::Interested {},
            3 => PeerMessageType::NotInterest {},
            4 => PeerMessageType::Have {},
            5 => PeerMessageType::Bitfield {},
            6 => PeerMessageType::Request {},
            7 => PeerMessageType::Piece {},
            b => PeerMessageType::Undefine { b },
        }
    }
}
pub struct PeerMessage {
    pub msg_type: PeerMessageType,
    payload: Vec<u8>,
}

impl PeerMessage {
    pub fn new_message(msg_type: PeerMessageType) -> Self {
        PeerMessage {
            msg_type,
            payload: vec![],
        }
    }

    pub fn new_request(index: u32, begin: u32, length: u32) -> Self {
        let mut payload = Vec::new();

        payload.extend(index.to_be_bytes());
        payload.extend(begin.to_be_bytes());
        payload.extend(length.to_be_bytes());

        PeerMessage {
            msg_type: PeerMessageType::Request,
            payload,
        }
    }

    pub fn form_bytes(b: &[u8; 5]) -> Self {
        PeerMessage {
            msg_type: PeerMessageType::from_byte(b[4]),
            payload: vec![],
        }
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut v = Vec::new();

        let msg_len = 4 + 1 + self.payload.len() as u32;

        v.extend(u32::to_be_bytes(msg_len));

        // Message ID
        v.extend(self.msg_type.to_byte().to_be_bytes());

        // payload
        v.extend(&self.payload);
        v
    }
}

impl HandshakeMessage {
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}
