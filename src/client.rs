use crate::connection::Connection;
use crate::crypto::ToPublicKey;
use crate::datagram::Datagram;
use crate::tl_types::{Answer, Ping, Pong, Query};
use anyhow::{anyhow, Result};
use rand::prelude::*;
use tokio::net::{TcpStream, ToSocketAddrs};

pub struct Client {
    connection: Connection,
}

impl Client {
    pub async fn connect<A, P>(addr: A, public: P) -> Result<Client>
    where
        A: ToSocketAddrs,
        P: ToPublicKey,
    {
        let tcp_stream = TcpStream::connect(addr).await?;
        let init_connection = Connection::new(tcp_stream);
        let enc_connection = init_connection
            .exchange_keys(public.to_public()?.as_bytes())
            .await?;
        let client = Client {
            connection: enc_connection,
        };

        Ok(client)
    }

    pub async fn ping(&mut self) -> Result<Pong> {
        let random_id = thread_rng().gen::<u64>();
        let req_datagram = Datagram::from_buf(&tl_proto::serialize(Ping { random_id }))?;

        self.connection.write_datagram(&req_datagram).await?;

        let res_datagram = self.connection.read_datagram().await?;
        if let Some(Datagram::Data { buffer, .. }) = res_datagram {
            let pong = tl_proto::deserialize::<Pong>(&buffer)?;
            return Ok(pong);
        } else {
            return Err(anyhow!("ping failed: invalid response datagram"));
        }
    }

    pub async fn query(&mut self, bytes: &[u8]) -> Result<Answer> {
        let mut query_id = [0u8; 32];
        thread_rng().fill_bytes(&mut query_id);
        let req_datagram = Datagram::from_buf(&tl_proto::serialize(Query {
            query_id,
            query_bytes: bytes.to_vec(),
        }))?;

        self.connection.write_datagram(&req_datagram).await?;

        let res_datagram = self.connection.read_datagram().await?;
        if let Some(Datagram::Data { buffer, .. }) = res_datagram {
            let answer = tl_proto::deserialize::<Answer>(&buffer)?;
            return Ok(answer);
        } else {
            return Err(anyhow!("query failed: invalid response datagram"));
        }
    }
}
