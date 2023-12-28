use anyhow::Ok;
use serde_json;
use std::{collections::HashMap, env};
use tracker::{TrackerRequest, TrackerResponse};
use urlencoding::encode;

mod meta;
mod tracker;

#[allow(dead_code)]
fn decode_bencoded_value(encoded_value: &str) -> (serde_json::Value, &str) {
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
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    let command = &args[1];

    if command == "decode" {
        let encoded_value = &args[2];
        let decoded_value = decode_bencoded_value(encoded_value);
        println!("{}", decoded_value.0.to_string());
    } else if command == "info" {
        let data = std::fs::read(&args[2]).expect("torrent file exist");

        let meta: meta::MetaInfo = serde_bencode::from_bytes(&data).expect("Meta");

        println!("Tracker URL: {}", meta.announce);
        println!("Length: {:?}", meta.info.length);

        println!("Info Hash: {}", meta.info_hash());

        println!("Piece Length: {}", meta.info.piece_length);

        println!("Piece Hashes:");
        meta.pieces_hash().iter().for_each(|v| println!("{v}"));
    } else if command == "peers" {
        let data = std::fs::read(&args[2]).expect("torrent file exist");

        let meta: meta::MetaInfo = serde_bencode::from_bytes(&data).expect("Meta");

        let mut url = reqwest::Url::parse(&meta.announce).expect("announce URL ");

        let encode_query = TrackerRequest::from(meta).query();
        url.set_query(Some(&encode_query));
        let b = reqwest::get(url).await?.bytes().await?;

        let resp: TrackerResponse = serde_bencode::from_bytes(&b).expect("Tracker response");

        resp.peers()
            .iter()
            .for_each(|v| println!("{}:{}", v.0, v.1));
    } else {
        println!("unknown command: {}", args[1])
    }

    Ok(())
}
