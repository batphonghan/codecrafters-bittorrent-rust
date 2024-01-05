use anyhow::Ok;
use clap::{Parser, Subcommand};
use hex::encode;
use hex::ToHex;
use peer::{HandshakeMessage, PeerMessage};
use serde_json;
use sha1::{Digest, Sha1};
use std::time::Duration;
use std::{env, path::PathBuf};
use tokio::fs::OpenOptions;
use tokio::io::AsyncReadExt;
use tokio::time::sleep;
use tokio::{fs::File, io::AsyncWriteExt, net::TcpStream};

use tracker::{TrackerRequest, TrackerResponse};
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
            let resp = get_tracker(path).await?;
            resp.peers()
                .iter()
                .for_each(|v| println!("{}:{}", v.0, v.1));
        }

        SubCommands::Handshake { path, peer } => {
            let data = std::fs::read(path).expect("torrent file exist");

            let meta: meta::MetaInfo = serde_bencode::from_bytes(&data).expect("Meta");

            // Connect to a peer
            let mut stream = TcpStream::connect(peer).await?;

            let handshake = HandshakeMessage::from(meta);
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
            let data = std::fs::read(path).expect("torrent file exist");
            let meta: meta::MetaInfo = serde_bencode::from_bytes(&data).expect("Meta");

            let piece_length = meta.info.piece_length;
            let file_length = meta.info.length;

            let pieces_hash = meta.pieces_hash();
            let piece_hash = pieces_hash.get(*piece).expect("piece at indexs");

            let trackers = get_tracker(path).await?;
            let peers = trackers.peers();
            let tracker = &peers.last().expect("at least one peer");

            let peer = format!("{}:{}", tracker.0, tracker.1);
            // Connect to a peer
            let mut stream = TcpStream::connect(peer).await?;

            let handshake = HandshakeMessage::from(meta);
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

            let mut v = [0; 5];

            eprintln!("wait for bitfield peer {:?}", peer_id);
            loop {
                stream.readable().await?;
                let _ = stream.try_read(&mut v);
                let msg_type =
                    peer::PeerMessage::form_bytes(&v[..5].try_into().expect("e")).msg_type;
                match msg_type {
                    peer::PeerMessageType::Bitfield { .. } => break,
                    _ => {
                        eprintln!("Got unexpected {:?} {:?}", v, msg_type);
                        sleep(Duration::from_secs(2)).await;
                    }
                };
            }

            eprintln!("received bitfield");

            let mut v = [0; 5];
            let interest_byte =
                peer::PeerMessage::new_message(peer::PeerMessageType::Interested).as_bytes();
            stream.write_all(&interest_byte[..]).await?;

            eprintln!("wait for unchoke");

            loop {
                stream.readable().await?;
                let _ = stream.try_read(&mut v);
                let msg_type = peer::PeerMessage::form_bytes(&v).msg_type;
                match msg_type {
                    peer::PeerMessageType::Unchoke { .. } => break,
                    _ => {
                        eprintln!("Got unexpected {:?} {:?}", v, msg_type);
                        // sleep(Duration::from_secs(2)).await;
                    }
                };
            }
            eprintln!("received for unchoke");

            const BLOCK_SIZE: usize = 16381; // 2 ^ 14

            // const piece_size: usize = BLOCK_SIZE + 64 + 5;

            let mut f = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .append(true)
                .open(output)
                .await?;

            let mut curr_offset = 0;
            let mut all_blocks: Vec<u8> = vec![0; piece_length];

            let mut index = 0;
            while curr_offset < piece_length {
                let mut curr_block_len = BLOCK_SIZE;
                if curr_offset + BLOCK_SIZE > piece_length {
                    curr_block_len = piece_length - curr_offset;
                }

                let request_msg = peer::PeerMessage::new_request(
                    *piece as u32,
                    curr_offset as u32,
                    curr_block_len as u32,
                )
                .as_bytes();
                stream.write_all(&request_msg[..]).await?;

                eprintln!(
                    "{index} Request piece at offset: {curr_offset} with length: {curr_block_len}. Total piece_length: {piece_length}"
                );
                index += 1;
                curr_offset += curr_block_len;
            }

            let mut block_received = 0;
            loop {
                let mut piece_msg_data = [0; 5];

                stream.readable().await?;
                let read_size = stream.read_exact(&mut piece_msg_data).await?;

                if read_size == 0 {
                    panic!("Closed");
                }

                // let (piece_msg_data, piece_payload) = piece_data.split_at(5);

                let msg_type =
                    peer::PeerMessage::form_bytes(&piece_msg_data.try_into().expect("5 byes"))
                        .msg_type;

                match msg_type {
                    peer::PeerMessageType::Piece { .. } => {
                        let length =
                            u32::from_be_bytes(piece_msg_data[..4].try_into().expect("4 bytes"));

                        // Read the payload
                        let mut piece_payload: Vec<u8> = vec![0; length as usize - 1];

                        stream.readable().await?;
                        let _ = stream.read_exact(&mut piece_payload).await;

                        // eprintln!("received for Piece");
                        let (index_byte, piece_payload) = piece_payload.split_at(4);

                        // eprintln!(
                        //     "Index {}",
                        //     u32::from_be_bytes(index_byte.try_into().expect("4 bytes u32 index"))
                        // );

                        let (begin, piece_payload) = piece_payload.split_at(4);

                        let begin = u32::from_be_bytes(begin.try_into().expect("4 bytes u32 begin"))
                            as usize;
                        // eprintln!("begin {}", begin);

                        // let piece_payload = &piece_payload[..curr_block_len];

                        let blocks = all_blocks[begin..begin + length as usize - 1 - 8].as_mut();
                        blocks.copy_from_slice(piece_payload);

                        block_received += blocks.len();
                        // break;

                        if block_received >= piece_length {
                            break;
                        }
                    }
                    _ => {
                        eprintln!("Got unexpected {:?} {:?}", v, msg_type);
                        sleep(Duration::from_secs(2)).await;
                    }
                };
            }
            // break;
            let mut hasher = Sha1::new();
            hasher.update(&all_blocks);
            let hash: [u8; 20] = hasher.finalize().try_into()?;

            assert_eq!(hash.encode_hex::<String>(), *piece_hash);

            assert_eq!(all_blocks.len(), piece_length);
            println!(
                "Piece {piece} downloaded to {}.",
                output.as_path().display()
            );

            f.write_all(&all_blocks).await?;
            let _ = f.flush();
        }
        _ => {
            println!("unknown command: {}", args[1])
        }
    }

    Ok(())
}

async fn get_tracker(path: &PathBuf) -> anyhow::Result<TrackerResponse> {
    let data = std::fs::read(path).expect("torrent file exist");

    let meta: meta::MetaInfo = serde_bencode::from_bytes(&data).expect("Meta");

    let mut url = reqwest::Url::parse(&meta.announce).expect("announce URL ");

    let encode_query = TrackerRequest::from(meta).query();
    url.set_query(Some(&encode_query));
    let b = reqwest::get(url).await?.bytes().await?;

    let resp: TrackerResponse = serde_bencode::from_bytes(&b).expect("Tracker response");

    Ok(resp)
}

// left: `"bdd62e4f018128f2475f5286156ac3fb02b5f42e"`,
// right: `"e876f67a2a8886e8f36b136726c30fa29703022d"`', src/main.rs:310:13
// note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace

// [your_program] 0 Request piece at offset: 0 with length: 16384. Total piece_length: 262144
// [your_program] 1 Request piece at offset: 16384 with length: 16384. Total piece_length: 262144
// [your_program] 2 Request piece at offset: 32768 with length: 16384. Total piece_length: 262144
// [your_program] 3 Request piece at offset: 49152 with length: 16384. Total piece_length: 262144
// [your_program] 4 Request piece at offset: 65536 with length: 16384. Total piece_length: 262144
// [your_program] 5 Request piece at offset: 81920 with length: 16384. Total piece_length: 262144
// [your_program] 6 Request piece at offset: 98304 with length: 16384. Total piece_length: 262144
// [your_program] 7 Request piece at offset: 114688 with length: 16384. Total piece_length: 262144
// [your_program] 8 Request piece at offset: 131072 with length: 16384. Total piece_length: 262144
// [your_program] 9 Request piece at offset: 147456 with length: 16384. Total piece_length: 262144
// [your_program] 10 Request piece at offset: 163840 with length: 16384. Total piece_length: 262144
// [your_program] 11 Request piece at offset: 180224 with length: 16384. Total piece_length: 262144
// [your_program] 12 Request piece at offset: 196608 with length: 16384. Total piece_length: 262144
// [your_program] 13 Request piece at offset: 212992 with length: 16384. Total piece_length: 262144
// [your_program] 14 Request piece at offset: 229376 with length: 16384. Total piece_length: 262144
// [your_program] 15 Request piece at offset: 245760 with length: 16384. Total piece_length: 262144

// 245760 + 16384
