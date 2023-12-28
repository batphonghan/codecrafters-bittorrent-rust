use crate::meta::{self, MetaInfo};

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

impl HandshakeMessage {
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}
