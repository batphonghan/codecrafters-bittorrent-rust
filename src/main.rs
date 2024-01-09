use anyhow::Context;
use clap::{Parser, Subcommand};
use hex::encode;
use hex::ToHex;
use peer::{HandshakeMessage, PeerMessage};
use serde_json;
use sha1::digest::crypto_common::KeyInit;
use sha1::{Digest, Sha1};
use std::result::Result::Ok;
use std::time::Duration;
use std::vec;
use std::{env, path::PathBuf};
use tokio::fs::read;
use tokio::fs::OpenOptions;
use tokio::io::BufReader;
use tokio::io::BufWriter;
use tokio::time::sleep;
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use download::Downloader;
use tracker::{TrackerRequest, TrackerResponse};

mod download;
mod meta;
mod peer;
mod tracker;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: SubCommands,
}

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

#[derive(Subcommand)]
#[clap(rename_all = "snake_case")]
enum SubCommands {
    /// does testing things
    Decode {
        value: String,
    },
    Info {
        path: PathBuf,
    },
    Peers {
        path: PathBuf,
    },
    Handshake {
        path: PathBuf,
        peer: String,
    },
    DownloadPiece {
        #[arg(short)]
        output: PathBuf,
        path: PathBuf,
        piece: usize,
    },
    Download {
        #[arg(short)]
        output: PathBuf,
        path: PathBuf,
    },
}

// Usage: your_bittorrent.sh decode "<encoded_value>"
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let args: Vec<String> = env::args().collect();

    match &cli.command {
        SubCommands::Decode {
            value: encoded_value,
        } => {
            let decoded_value = decode_bencoded_value(encoded_value);
            println!("{}", decoded_value.0.to_string());
        }
        SubCommands::Info { path } => {
            let data = std::fs::read(path).expect("torrent file exist");

            let meta: meta::MetaInfo = serde_bencode::from_bytes(&data).expect("Meta");

            println!("Tracker URL: {}", meta.announce);
            println!("Length: {:?}", meta.info.length);

            println!("Info Hash: {}", meta.info_hash());

            println!("Piece Length: {}", meta.info.piece_length);

            println!("Piece Hashes:");
            meta.pieces_hash().iter().for_each(|v| println!("{v}"));
        }
        SubCommands::Peers { path } => {
            let resp = download::get_tracker(path).await?;
            resp.peers()
                .iter()
                .for_each(|v| println!("{}:{}", v.0, v.1));
        }

        SubCommands::Handshake { path, peer } => {
            let data = std::fs::read(path).expect("torrent file exist");

            let meta: meta::MetaInfo = serde_bencode::from_bytes(&data).expect("Meta");

            // Connect to a peer
            let mut stream = TcpStream::connect(peer).await?;

            let handshake = HandshakeMessage::from(&meta);
            // Write some data.
            let mut handshake_bytes: Vec<u8> = handshake.into_bytes();
            stream.write_all(&handshake_bytes[..]).await?;

            // Wait for the socket to be readable
            stream.readable().await?;

            // Try to read data, this may still fail with `WouldBlock`
            // if the readiness event is a false positive.
            stream
                .try_read(&mut handshake_bytes)
                .expect("Read handshake");

            // last 20 bytes
            let peer_id = &handshake_bytes[48..];
            println!("Peer ID: {}", encode(peer_id));
        }
        SubCommands::DownloadPiece {
            output,
            path,
            piece,
        } => {
            let data = read(path).await.expect("torrent file exist");
            let meta: meta::MetaInfo = serde_bencode::from_bytes(&data).expect("Meta");

            let mut downloader = Downloader::new(meta, path).await?;

            downloader.handshake().await?;

            downloader.wait_bitfield().await?;

            downloader.wait_unchoke().await?;

            downloader.download_piece(output, piece).await?;
        }
        SubCommands::Download { output, path } => {
            let data = read(path).await.expect("torrent file exist");
            let meta: meta::MetaInfo = serde_bencode::from_bytes(&data).expect("Meta");

            let mut downloader = Downloader::new(meta, path).await?;

            downloader.handshake().await?;

            downloader.wait_bitfield().await?;

            downloader.wait_unchoke().await?;

            downloader.download_file(output).await?;
        }
    }

    Ok(())
}
