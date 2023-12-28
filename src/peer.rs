use crate::meta::{self, MetaInfo};

pub struct HandshakeMessage(Vec<u8>);

// 1 + 19 + 8 + 20 + 20 => 68
impl From<MetaInfo> for HandshakeMessage {
    fn from(meta: meta::MetaInfo) -> HandshakeMessage {
        let mut encode = Vec::new();

        let length: u8 = 19;
        let b_byte: [u8; 1] = length.to_be_bytes();
        encode.extend(b_byte);

        encode.extend(b"BitTorrent protocol");

        let reserved: [u8; 8] = [0; 8];
        encode.extend(reserved);

        let info_hash = meta.info_hash_byte();
        encode.extend(info_hash);

        encode.extend(b"00112233445566778899");

        assert_eq!(encode.len(), 68);

        HandshakeMessage(encode)
    }
}

impl Into<Vec<u8>> for HandshakeMessage {
    fn into(self) -> Vec<u8> {
        self.0
    }
}
