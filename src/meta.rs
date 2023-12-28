use hex::ToHex;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct MetaInfo {
    pub announce: String,
    pub info: Info,
}
/*  */
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct Info {
    pub length: i64,
    pub name: String,
    #[serde(rename = "piece length")]
    pub piece_length: usize,
    /// Each entry of `pieces` is the SHA1 hash of the piece at the corresponding index.
    pub pieces: serde_bencode::value::Value,
}

impl MetaInfo {
    pub fn info_hash(&self) -> String {
        let b = self.info_hash_byte();
        b.encode_hex()
    }

    pub fn info_hash_byte(&self) -> [u8; 20] {
        let info = serde_bencode::to_bytes(&self.info).expect("encode info");
        let hasher = hashes::sha1::hash(&info);
        hasher.into_bytes()
    }

    pub fn pieces_hash(&self) -> Vec<String> {
        match self.info.pieces {
            serde_bencode::value::Value::Bytes(ref buf) => {
                buf.chunks(20).map(|v| v.encode_hex::<String>()).collect()
            }
            _ => vec![],
        }
    }
}
