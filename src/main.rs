use reqwest::Url;
use serde_json;
use std::{
    collections::{BTreeMap, HashMap},
    env,
};

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct MetaInfo {
    announce: String,
    // #[serde(flatten)]
    info: Info,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct Info {
    length: usize,
    name: String,
    #[serde(rename = "piece length")]
    piece_length: usize,
    // pieces60: Vec<u8>,
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
        // You can use print statements as follows for debugging, they'll be visible when running tests.
        // println!("Logs from your program will appear here!");

        // Uncomment this block to pass the first stage
        let encoded_value = &args[2];
        let decoded_value = decode_bencoded_value(encoded_value);
        println!("{}", decoded_value.0.to_string());
    } else if command == "info" {
        let data = std::fs::read(&args[2]).expect("torrent file exist");

        let meta: MetaInfo = serde_bencode::from_bytes(&data).expect("Meta");

        println!("Tracker URL: {}", meta.announce);
        println!("Length: {}", meta.info.length);
        // println!("Meta: {:?}", meta);
    } else {
        println!("unknown command: {}", args[1])
    }
}

#[test]
fn it_works() {
    let (v, s) = decode_bencoded_value("lli4eei5ee");

    //l < l< i4e e i5 >e >e
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
