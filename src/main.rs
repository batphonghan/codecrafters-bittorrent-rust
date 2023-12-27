use serde_json;
use std::env;

use hex::ToHex;

use serde::{Deserialize, Serialize};
//d69f91e6b2ae4c542468d1073a71d4ea13879a7f
// e876f67a2a8886e8f36b136726c30fa29703022d6e2275e604a0766656736e81ff10b55204ad8d35f00d937a0213df1982bc8d097227ad9e909acc17
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct MetaInfo {
    announce: String,
    // #[serde(flatten)]
    info: Info,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct Info {
    length: i64,
    name: String,
    #[serde(rename = "piece length")]
    piece_length: usize,
    /// Each entry of `pieces` is the SHA1 hash of the piece at the corresponding index.
    pieces: serde_bencode::value::Value,
}

// Available if you need it!
// use serde_bencode

#[allow(dead_code)]
fn decode_bencoded_value(encoded_value: &str) -> (serde_json::Value, &str) {
    // If encoded_value starts with a digit, it's a number

    let (tag, mut rest) = encoded_value.split_at(1);
    let tag = &tag.chars().next().expect("split at");
    match tag {
        'i' => {
            if let Some((digit, rest)) = rest.split_once('e') {
                if let Some(len) = digit.parse::<i64>().ok() {
                    return (len.into(), rest);
                }
            }
        }
        'l' => {
            let mut values = Vec::new();
            while !rest.is_empty() {
                // End of all list element
                if rest.starts_with('e') {
                    return (values.into(), &rest[1..]);
                }

                let (v, remainder) = decode_bencoded_value(rest);
                if !v.is_null() {
                    values.push(v);
                }

                rest = remainder
            }
            return (values.into(), &rest);
        }
        'd' => {
            let mut values = serde_json::Map::new();

            while !rest.is_empty() {
                // End of all dict keys + values
                if rest.starts_with('e') {
                    return (values.into(), &rest[1..]);
                }

                let (key, remainder) = decode_bencoded_value(rest);
                let (value, remainder) = decode_bencoded_value(remainder);
                match key {
                    serde_json::Value::String(s) => values.insert(s, value),
                    _ => panic!("Unsupport type keys"),
                };

                rest = remainder;
            }

            return (values.into(), &rest);
        }
        _ => {
            if let Some((len, rest)) = encoded_value.split_once(':') {
                if let Some(len) = len.parse::<usize>().ok() {
                    return (serde_json::Value::String(rest[..len].into()), &rest[len..]);
                }
            }
        }
    }

    return (serde_json::Value::Null, "");
}

// Usage: your_bittorrent.sh decode "<encoded_value>"
fn main() {
    let args: Vec<String> = env::args().collect();
    let command = &args[1];

    if command == "decode" {
        let encoded_value = &args[2];
        let decoded_value = decode_bencoded_value(encoded_value);
        println!("{}", decoded_value.0.to_string());
    } else if command == "info" {
        let data = std::fs::read(&args[2]).expect("torrent file exist");

        let meta: MetaInfo = serde_bencode::from_bytes(&data).expect("Meta");

        println!("Tracker URL: {}", meta.announce);
        println!("Length: {:?}", meta.info.length);

        let info = serde_bencode::to_bytes(&meta.info).expect("encode info");
        let hasher = hashes::sha1::hash(&info);
        let b = hasher.into_bytes();

        println!("Info Hash: {}", b.encode_hex::<String>());

        println!("Piece Length: {}", meta.info.piece_length);

        println!("Piece Hashes:");
        match meta.info.pieces {
            serde_bencode::value::Value::Bytes(ref buf) => {
                let c: Vec<_> = buf.chunks(20).collect();
                c.iter()
                    .for_each(|v| println!("{}", v.encode_hex::<String>()));
            }
            _ => {}
        };
    } else {
        println!("unknown command: {}", args[1])
    }
}

#[test]
fn it_works() {
    let (v, s) = decode_bencoded_value("lli4eei5ee");

    assert!(s.is_empty(), "s is fully parsed");

    println!("{:?}", v);
}

#[test]
fn it_works_dict() {
    let (v, s) = decode_bencoded_value("d3:foo3:bar5:helloi52ee");

    //l < l< i4e e i5 >e >e
    assert!(s.is_empty(), "s is fully parsed");

    println!("{:?}", v);
}
