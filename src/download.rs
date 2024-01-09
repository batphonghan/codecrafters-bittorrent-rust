use crate::peer;
use crate::{
    meta::{self, Info, MetaInfo},
    peer::HandshakeMessage,
    tracker::{TrackerRequest, TrackerResponse},
};

use anyhow::Context;
use hex::ToHex;
use sha1::{Digest, Sha1};
use std::path::PathBuf;
use tokio::fs::OpenOptions;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const BLOCK_SIZE: usize = 1 << 14;
pub struct Downloader {
    meta: MetaInfo,
    stream: TcpStream,
}

impl Downloader {
    pub async fn new(meta: MetaInfo, path: &PathBuf) -> anyhow::Result<Self> {
        let trackers = get_tracker(path).await?;

        let peers = trackers.peers();
        let tracker = &peers.last().expect("at least one peer");

        let peer = format!("{}:{}", tracker.0, tracker.1);
        // Connect to a peer
        let stream = TcpStream::connect(peer).await?;

        Ok(Downloader { meta, stream })
    }

    pub async fn handshake(&mut self) -> anyhow::Result<()> {
        let handshake = HandshakeMessage::from(&self.meta);
        let mut handshake_bytes: Vec<u8> = handshake.into_bytes();
        self.stream.write_all(&handshake_bytes[..]).await?;

        eprintln!("Wait for hanshake reable");
        // Wait for the socket to be readable
        self.stream.readable().await?;

        eprintln!("Wait for hanshake back");

        self.stream.readable().await?;

        self.stream.read_exact(&mut handshake_bytes).await?;

        Ok(())
    }

    pub async fn wait_bitfield(&mut self) -> anyhow::Result<()> {
        let mut v = [0; 5];
        let _ = self
            .stream
            .read_exact(&mut v)
            .await
            .expect("read exact for bitfield");

        let msg_type = peer::PeerMessage::form_bytes(&v[..5].try_into().expect("e")).msg_type;

        match msg_type {
            peer::PeerMessageType::Bitfield { .. } => {}
            _ => {
                panic!("not epexted");
            }
        };

        let bitfield_len = u32::from_be_bytes(v[0..4].try_into().expect("first 4 bytes")) as usize;
        eprintln!("received bitfield");

        let mut rest = vec![0; bitfield_len - 1];

        self.stream.readable().await?;
        let _ = self.stream.read_exact(&mut rest).await?;
        eprintln!("readed rest bitfield {}", rest.len());

        Ok(())
    }

    pub async fn wait_unchoke(&mut self) -> anyhow::Result<()> {
        let mut v = [0; 5];
        let interest_byte =
            peer::PeerMessage::new_message(peer::PeerMessageType::Interested).as_bytes();
        self.stream.write_all(&interest_byte[..]).await?;

        self.stream.readable().await?;
        let _ = self.stream.read_exact(&mut v).await?;
        let msg_type = peer::PeerMessage::form_bytes(&v).msg_type;
        match msg_type {
            peer::PeerMessageType::Unchoke { .. } => {}
            _ => {
                panic!("not epexted");
            }
        };
        eprintln!("received for unchoke");

        Ok(())
    }

    pub async fn download_piece(&mut self, output: &PathBuf, piece: &usize) -> anyhow::Result<()> {
        let piece_length = self.meta.info.piece_length as usize;
        let file_length = self.meta.info.length;

        let pieces_hash = self.meta.pieces_hash();

        let npiece = (file_length as usize + (piece_length - 1)) / piece_length;

        let piece_hash = pieces_hash.get(*piece).expect("piece at indexs");

        let piece_length = if *piece == npiece - 1 {
            let md = file_length as usize % piece_length;
            if md == 0 {
                piece_length
            } else {
                md
            }
        } else {
            piece_length
        };

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

        let nblocks = (piece_length + (BLOCK_SIZE - 1)) / BLOCK_SIZE;

        for block in 0..nblocks {
            let mut curr_block_len = BLOCK_SIZE;
            if curr_offset + BLOCK_SIZE >= piece_length {
                curr_block_len = piece_length - curr_offset;
            }

            let block_size = if block == nblocks - 1 {
                let md = piece_length % BLOCK_SIZE;
                if md == 0 {
                    BLOCK_SIZE
                } else {
                    md
                }
            } else {
                BLOCK_SIZE
            };

            let request_msg = peer::PeerMessage::new_request(
                *piece as u32,
                (block * BLOCK_SIZE) as u32,
                block_size as u32,
            )
            .as_bytes();
            self.stream.write_all(&request_msg[..]).await?;

            eprintln!(
                    "{index} Request piece at offset: {curr_offset} with length: {curr_block_len}. Total piece_length: {piece_length}"
                );
            index += 1;
            curr_offset += curr_block_len;
        }

        let mut block_received = 0;
        loop {
            if block_received >= piece_length {
                break;
            }

            let mut piece_msg_data = [0; 5];

            self.stream.readable().await?;
            let _ = self
                .stream
                .read_exact(&mut piece_msg_data)
                .await
                .context("Read piece message")?;

            let msg_type =
                peer::PeerMessage::form_bytes(&piece_msg_data.try_into().expect("5 byes")).msg_type;

            match msg_type {
                peer::PeerMessageType::Piece { .. } => {
                    let length =
                        i32::from_be_bytes(piece_msg_data[..4].try_into().expect("4 bytes"));

                    // Read the payload
                    let mut piece_payload: Vec<u8> = vec![0; length as usize - 1];

                    let _ = self
                        .stream
                        .read_exact(&mut piece_payload)
                        .await
                        .context("read exact piece payload")?;

                    let (index_byte, piece_payload) = piece_payload.split_at(4);

                    eprintln!(
                        "Index {}",
                        u32::from_be_bytes(index_byte.try_into().expect("4 bytes u32 index"))
                    );

                    let (begin, piece_payload) = piece_payload.split_at(4);

                    let begin =
                        u32::from_be_bytes(begin.try_into().expect("4 bytes u32 begin")) as usize;
                    eprintln!("begin {}", begin);

                    let blocks = all_blocks[begin..begin + length as usize - 1 - 8].as_mut();
                    blocks.copy_from_slice(piece_payload);

                    block_received += blocks.len();
                    // break;

                    if block_received >= piece_length {
                        break;
                    }
                }
                _ => {}
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

        Ok(())
    }

    pub async fn download_file(&mut self, output: &PathBuf) -> anyhow::Result<()> {
        let piece_length = self.meta.info.piece_length as usize;
        let file_length = self.meta.info.length;

        let npiece = (file_length as usize + (piece_length - 1)) / piece_length;

        for piece in 0..npiece {
            self.download_piece(output, &piece).await?
        }

        Ok(())
    }
}

pub async fn get_tracker(path: &PathBuf) -> anyhow::Result<TrackerResponse> {
    let data = std::fs::read(path).expect("torrent file exist");

    let meta: meta::MetaInfo = serde_bencode::from_bytes(&data).expect("Meta");

    let mut url = reqwest::Url::parse(&meta.announce).expect("announce URL ");

    let encode_query = TrackerRequest::from(meta).query();
    url.set_query(Some(&encode_query));
    let b = reqwest::get(url).await?.bytes().await?;

    let resp: TrackerResponse = serde_bencode::from_bytes(&b).expect("Tracker response");

    Ok(resp)
}
