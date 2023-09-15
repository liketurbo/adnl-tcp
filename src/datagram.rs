use crate::Result;
use bytes::{Buf, BytesMut};
use rand::prelude::*;
use sha2::{Digest, Sha256};
use std::io::Cursor;

const LENGTH_LEN: usize = 4;
const NONCE_LEN: usize = 32;
const BUFFER_LEN: usize = 64;
const HASH_LEN: usize = 32;

/// Represents a Datagram for secure communication.
///
/// | Parameter  | Size              | Notes                                                     |
/// |------------|-------------------|-----------------------------------------------------------|
/// | `length`   | 4 bytes (LE)      | Length of the whole datagram, excluding the length field  |
/// | `nonce`    | 32 bytes          | Random value                                              |
/// | `buffer`   | length - 64 bytes | Actual data to be sent to the other side                  |
/// | `hash`     | 32 bytes          | SHA-256(nonce || buffer) to ensure integrity              |
///
/// More information can be found in the https://docs.ton.org/learn/networking/low-level-adnl#datagram.
#[derive(Debug)]
pub enum Datagram {
    Empty {
        length: usize,
        nonce: [u8; NONCE_LEN],
        hash: [u8; HASH_LEN],
    },
    Data {
        length: usize,
        nonce: [u8; NONCE_LEN],
        buffer: Vec<u8>,
        hash: [u8; HASH_LEN],
    },
}

impl Datagram {
    fn new(len: usize, nonce: [u8; NONCE_LEN], buf: Vec<u8>, hash: [u8; HASH_LEN]) -> Self {
        let new_datagram = Datagram::Data {
            length: len,
            nonce,
            buffer: buf,
            hash,
        };
        new_datagram
    }

    /// Checks if an entire datagram can be decoded from `src`
    pub fn check(src: &mut Cursor<&[u8]>) -> bool {
        src.remaining() >= LENGTH_LEN + NONCE_LEN + HASH_LEN
            && src.get_u32_le() >= src.remaining() as u32
    }

    /// The datagram has already been validated with `check`.
    pub fn parse(src: &mut Cursor<&[u8]>) -> Result<Datagram> {
        let len = src.get_u32_le() as usize;

        let mut nonce_bytes = [0u8; NONCE_LEN];
        src.copy_to_slice(&mut nonce_bytes);

        if len == NONCE_LEN + HASH_LEN {
            let mut hash_bytes = [0u8; HASH_LEN];
            src.copy_to_slice(&mut hash_bytes);

            let nonce_hash = Sha256::new().chain_update(&nonce_bytes).finalize();
            if nonce_hash[..] != hash_bytes[..] {
                return Err("corrupted datagram".into());
            }

            return Ok(Datagram::Empty {
                length: len,
                nonce: nonce_bytes,
                hash: hash_bytes,
            });
        }

        let mut buf = Vec::with_capacity(BUFFER_LEN);
        let data = src.copy_to_bytes(len - NONCE_LEN - HASH_LEN);
        buf.extend_from_slice(&data);

        let mut hash_bytes = [0u8; HASH_LEN];
        src.copy_to_slice(&mut hash_bytes);

        let datagram_hash = Sha256::new()
            .chain_update(&nonce_bytes)
            .chain_update(&buf)
            .finalize();

        if datagram_hash[..] != hash_bytes[..] {
            return Err("corrupted datagram".into());
        }

        Ok(Datagram::new(len, nonce_bytes, buf, hash_bytes))
    }

    pub fn to_bytes(&self) -> BytesMut {
        match self {
            Datagram::Empty {
                length,
                nonce,
                hash,
            } => {
                let mut bytes = BytesMut::with_capacity(LENGTH_LEN + NONCE_LEN + HASH_LEN);
                bytes.extend_from_slice(&(*length as u32).to_le_bytes());
                bytes.extend_from_slice(nonce);
                bytes.extend_from_slice(hash);
                return bytes;
            }
            Datagram::Data {
                length,
                nonce,
                buffer,
                hash,
            } => {
                let mut bytes =
                    BytesMut::with_capacity(LENGTH_LEN + NONCE_LEN + BUFFER_LEN + HASH_LEN);
                bytes.extend_from_slice(&(*length as u32).to_le_bytes());
                bytes.extend_from_slice(nonce);
                bytes.extend_from_slice(&buffer);
                bytes.extend_from_slice(hash);
                return bytes;
            }
        }
    }

    pub fn from_buf(buf: &[u8]) -> Result<Datagram> {
        if buf.len() > BUFFER_LEN {
            return Err("datagram size exceeded".into());
        }

        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);

        let mut buf_bytes = Vec::with_capacity(BUFFER_LEN);
        buf_bytes.extend_from_slice(buf);

        let hash: [u8; HASH_LEN] = Sha256::new()
            .chain_update(&nonce_bytes)
            .chain_update(&buf_bytes)
            .finalize()
            .into();

        Ok(Datagram::new(
            NONCE_LEN + buf.len() + HASH_LEN,
            nonce_bytes,
            buf_bytes,
            hash,
        ))
    }
}
