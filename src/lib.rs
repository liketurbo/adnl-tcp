mod client;
mod connection;
mod crypto;
mod datagram;
mod tl_types;

pub use client::Client;
pub use crypto::ToPublicKey;

pub type Result<T> = std::result::Result<T, Error>;
pub type Error = Box<dyn std::error::Error>;
