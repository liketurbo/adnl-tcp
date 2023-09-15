use tl_proto::{TlRead, TlWrite};

#[derive(TlRead, TlWrite, Debug)]
#[tl(
    boxed,
    id = "tcp.ping",
    scheme_inline = r"tcp.ping random_id:long = tcp.Pong;"
)]
pub struct Ping {
    pub random_id: u64,
}

#[derive(TlRead, TlWrite, Debug)]
#[tl(
    boxed,
    id = "tcp.pong",
    scheme_inline = r"tcp.pong random_id:long = tcp.Pong;"
)]
pub struct Pong {
    pub random_id: u64,
}

#[derive(TlRead, TlWrite, Debug)]
#[tl(
    boxed,
    id = "adnl.message.query",
    scheme_inline = r"adnl.message.query query_id:int256 query:bytes = adnl.Message;"
)]
pub struct Query {
    pub query_id: [u8; 32],
    pub query_bytes: Vec<u8>,
}

#[derive(TlRead, TlWrite, Debug)]
#[tl(
    boxed,
    id = "adnl.message.answer",
    scheme_inline = r"adnl.message.answer query_id:int256 answer:bytes = adnl.Message;"
)]
pub struct Answer {
    pub query_id: [u8; 32],
    pub answer: Vec<u8>,
}
