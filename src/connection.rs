use crate::{
    crypto::{ed25519_to_x25519, encrypt_aes_params, gen_key_id, x25519_to_ed25519, AesCipher},
    datagram::Datagram,
    Result,
};
use bytes::{Buf, BytesMut};
use ctr::cipher::{KeyIvInit, StreamCipher};
use rand::prelude::*;
use sha2::{Digest, Sha256};
use std::io::Cursor;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::{io::BufWriter, net::TcpStream};
use x25519_dalek::{EphemeralSecret, PublicKey};

pub enum Connection {
    Init {
        stream: BufWriter<TcpStream>,
        buffer: BytesMut,
    },
    Enc {
        stream: BufWriter<TcpStream>,
        buffer: BytesMut,
        rx_cipher: AesCipher,
        tx_cipher: AesCipher,
    },
}

impl Connection {
    pub fn new(tcp_stream: TcpStream) -> Connection {
        Connection::Init {
            stream: BufWriter::new(tcp_stream),
            buffer: BytesMut::default(),
        }
    }

    pub async fn exchange_keys(self, receiver_public: &[u8; 32]) -> Result<Connection> {
        if let Connection::Init { mut stream, .. } = self {
            let my_secret = EphemeralSecret::random();
            let my_public = PublicKey::from(&my_secret);
            let receiver_public_x25519 = PublicKey::from(ed25519_to_x25519(receiver_public)?);
            let shared_key = my_secret.diffie_hellman(&receiver_public_x25519);

            // Represents AES-CTR session parameters.
            //
            // | Parameter  | Size     |
            // |------------|----------|
            // | `rx_key`   | 32 bytes |
            // | `tx_key`   | 32 bytes |
            // | `rx_nonce` | 16 bytes |
            // | `tx_nonce` | 16 bytes |
            // | `padding`  | 64 bytes |
            //
            // More information can be found in the https://docs.ton.org/learn/networking/low-level-adnl#handshake.
            let mut aes_params = [0u8; 160];
            rand::thread_rng().fill_bytes(&mut aes_params);

            let rx_cipher =
                AesCipher::new(aes_params[..32].try_into()?, aes_params[64..80].try_into()?);
            let tx_cipher = AesCipher::new(
                aes_params[32..64].try_into()?,
                aes_params[80..96].try_into()?,
            );

            // Represents a 256-bytes handshake packet for secure communication.
            //
            // | Parameter             | Size      | Notes                                                          |
            // |-----------------------|-----------|----------------------------------------------------------------|
            // | `receiver_address`    | 32 bytes  | Server peer identity as described in the corresponding section |
            // | `sender_public`       | 32 bytes  | Client public key                                              |
            // | `sha256_aes_params`   | 32 bytes  | Integrity proof of session parameters using SHA-256            |
            // | `encrypted_aes_params`| 160 bytes | Encrypted session parameters using AES encryption              |
            //
            // More information can be found in the https://docs.ton.org/learn/networking/low-level-adnl#handshake.
            let mut bytes = BytesMut::with_capacity(32 + 32 + 32 + 160);

            let key_id = gen_key_id(&receiver_public);
            bytes.extend_from_slice(&key_id);

            let my_public_ed25519 = x25519_to_ed25519(my_public.as_bytes())?;
            bytes.extend_from_slice(&my_public_ed25519);

            let aes_params_hash = Sha256::new().chain_update(aes_params).finalize();
            bytes.extend_from_slice(&aes_params_hash);

            encrypt_aes_params(
                &mut aes_params,
                &aes_params_hash.into(),
                shared_key.as_bytes(),
            );
            bytes.extend_from_slice(&aes_params);

            while bytes.has_remaining() {
                let sent = stream.write(bytes.chunk()).await?;
                bytes.advance(sent);
            }
            stream.flush().await?;

            let mut enc_connection = Connection::Enc {
                stream,
                buffer: BytesMut::default(),
                rx_cipher,
                tx_cipher,
            };

            let datagram = enc_connection.read_datagram().await?;

            if let Some(Datagram::Empty { .. }) = datagram {
                return Ok(enc_connection);
            }

            return Err("handshake failed".into());
        }

        Err("keys exchange only possible for init connection".into())
    }

    pub async fn read_datagram(&mut self) -> Result<Option<Datagram>> {
        if let Connection::Enc {
            stream,
            buffer,
            rx_cipher,
            ..
        } = self
        {
            loop {
                let mut buf = Cursor::new(&buffer[..]);

                if Datagram::check(&mut buf) {
                    buf.set_position(0); // Reset after check
                    if let datagram = Datagram::parse(&mut buf)? {
                        buffer.advance(buf.position() as usize);
                        return Ok(Some(datagram));
                    }
                }

                let len = buffer.len();

                if stream.read_buf(buffer).await? == 0 {
                    if buffer.is_empty() {
                        return Ok(None);
                    }
                    return Err("connection reset by peer".into());
                }

                rx_cipher.apply_keystream(&mut buffer[len..]);
            }
        }

        Err("datagram read only possible for enc connection".into())
    }

    pub async fn write_datagram(&mut self, datagram: &Datagram) -> Result<usize> {
        if let Connection::Enc {
            stream, tx_cipher, ..
        } = self
        {
            let mut bytes = datagram.to_bytes();
            let bytes_len = bytes.len();

            tx_cipher.apply_keystream(&mut bytes[..]);

            while bytes.has_remaining() {
                let sent = stream.write(bytes.chunk()).await?;
                bytes.advance(sent);
            }
            stream.flush().await?;

            return Ok(bytes_len);
        }

        Err("datagram write only possible for enc connection".into())
    }
}
