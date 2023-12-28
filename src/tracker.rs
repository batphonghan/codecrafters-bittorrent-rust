use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::meta::MetaInfo;

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct TrackerRequest {
    ///the info hash of the torrent
    /// 20 bytes long, will need to be URL encoded
    /// Note: this is NOT the hexadecimal representation, which is 40 bytes long
    info_hash: [u8; 20],

    /// peer_id: a unique identifier for your client
    /// A string of length 20 that you get to pick. You can use something like 00112233445566778899.
    peer_id: String,

    /// port: the port your client is listening on
    /// You can set this to 6881, you will not have to support this functionality during this challenge.
    port: usize,

    /// uploaded: the total amount uploaded so far
    /// Since your client hasn't uploaded anything yet, you can set this to 0.
    uploaded: i64,

    // downloaded: the total amount downloaded so far
    // Since your client hasn't downloaded anything yet, you can set this to 0.
    downloaded: i64,

    // left: the number of bytes left to download
    // Since you client hasn't downloaded anything yet, this'll be the total length of the file (you've extracted this value from the torrent file in previous stages)
    left: i64,

    // compact: whether the peer list should use the compact representation
    // For the purposes of this challenge, set this to 1.
    // The compact representation is more commonly used in the wild, the non-compact representation is mostly supported for backward-compatibility.
    compact: u8,
}

// The tracker's response will be a bencoded dictionary with two keys:
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct TrackerResponse {
    // An integer, indicating how often your client should make a request to the tracker.
    // You can ignore this value for the purposes of this challenge.
    interval: usize,

    // A string, which contains list of peers that your client can connect to.
    // Each peer is represented using 6 bytes. The first 4 bytes are the peer's IP address and the last 2 bytes are the peer's port number.
    peers: serde_bencode::value::Value,
}

impl From<MetaInfo> for TrackerRequest {
    fn from(value: MetaInfo) -> Self {
        TrackerRequest {
            info_hash: value.info_hash_byte(),
            peer_id: "00112233445566778899".to_string(),
            port: 6881,
            uploaded: 0,
            downloaded: 0,
            left: value.info.length,
            compact: 1,
        }
    }
}

impl<'a> TrackerRequest {
    pub fn query(&'a self) -> String {
        let url_encoded_info_hash = urlencoding::encode_binary(&self.info_hash[..]);
        let url_encoded_peer_id = urlencoding::encode(&self.peer_id);

        let mut encode_str = String::new();

        encode_str.push_str("info_hash=");
        encode_str.push_str(&url_encoded_info_hash);
        encode_str.push('&');
        encode_str.push_str("peer_id=");
        encode_str.push_str(&url_encoded_peer_id);
        encode_str.push('&');
        encode_str.push_str("port=");
        encode_str.push_str(&self.port.to_string());
        encode_str.push('&');
        encode_str.push_str("uploaded=");
        encode_str.push_str(&self.uploaded.to_string());
        encode_str.push('&');
        encode_str.push_str("downloaded=");
        encode_str.push_str(&self.downloaded.to_string());
        encode_str.push('&');
        encode_str.push_str("left=");
        encode_str.push_str(&self.left.to_string());
        encode_str.push('&');
        encode_str.push_str("compact=");
        encode_str.push_str(&(self.compact as u8).to_string());
        encode_str
    }
}

impl TrackerResponse {
    pub fn peers(&self) -> Vec<(IpAddr, u16)> {
        match self.peers {
            serde_bencode::value::Value::Bytes(ref buf) => buf
                .chunks(6)
                .map(|v| {
                    let (ip_b, port) = v.split_at(4);

                    let first_4_bytes: [u8; 4] = ip_b.try_into().expect("4 bytes IPv4");
                    let ip = IpAddr::from(first_4_bytes);

                    let last_2_bytes: [u8; 2] = port.try_into().expect("2 bytes port");
                    let port = u16::from_be_bytes(last_2_bytes);

                    (ip, port)
                })
                .collect(),
            _ => vec![],
        }
    }
}
