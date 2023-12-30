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
    Interest,
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
            PeerMessageType::Interest => 2,
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
            2 => PeerMessageType::Interest {},
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
    prefix: [u8; 4],
    // message_id: [u8; 1],
    pub msg_type: PeerMessageType,
    payload: Vec<u8>,
}

impl PeerMessage {
    pub fn new(msg_type: PeerMessageType, payload: Vec<u8>) -> Self {
        let mut prefix = [0; 4];
        prefix[3] = msg_type.to_byte();

        PeerMessage {
            msg_type,
            payload,
            prefix,
        }
    }

    pub fn form_bytes(b: &[u8; 5], payload: Vec<u8>) -> Self {
        PeerMessage {
            prefix: b[..4].try_into().expect("4 bytes prefix"),
            msg_type: PeerMessageType::from_byte(b[4]),
            payload,
        }
    }

    pub fn bytes(&self) -> Vec<u8> {
        let mut v = Vec::new();

        v.extend(self.prefix);

        v.push(self.msg_type.to_byte());

        v.extend(&self.payload);
        v
    }
}

impl HandshakeMessage {
    // pub fn new(info_hash: [u8; 20]) -> Self {
    //     let inner = InnerHandshake::new(info_hash);

    //     let b = serde_bytes::serialize(inner).expect("deserialize");

    //     HandshakeMessage {}
    // }
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

#[derive(Deserialize, Serialize)]
struct InnerHandshake {
    length: u8,
    protocol: [u8; 19],
    reserved: [u8; 8],
    info_hash: [u8; 20],
    peer_id: [u8; 20],
}

// impl InnerHandshake {
//     fn new(info_hash: [u8; 20]) -> Self {
//         InnerHandshake {
//             length: 19,
//             protocol: *b"BitTorrent protocol",
//             reserved: [0; 8],
//             info_hash,
//             peer_id: *b"00112233445566778899",
//         }
//     }
// }

#[repr(C)]
#[repr(packed)]
#[derive(Debug)]
pub struct Request {
    index: [u8; 4],
    begin: [u8; 4],
    length: [u8; 4],
}

impl Request {
    pub fn new(index: u32, begin: u32, length: u32) -> Self {
        Self {
            index: index.to_be_bytes(),
            begin: begin.to_be_bytes(),
            length: length.to_be_bytes(),
        }
    }

    pub fn index(&self) -> u32 {
        u32::from_be_bytes(self.index)
    }

    pub fn begin(&self) -> u32 {
        u32::from_be_bytes(self.begin)
    }

    pub fn length(&self) -> u32 {
        u32::from_be_bytes(self.length)
    }

    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        let bytes = self as *mut Self as *mut [u8; std::mem::size_of::<Self>()];
        // Safety: Self is a POD with repr(c) and repr(packed)
        let bytes: &mut [u8; std::mem::size_of::<Self>()] = unsafe { &mut *bytes };
        bytes
    }
}
