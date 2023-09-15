# ADNL TCP

This is an **incomplete**, simplified implementation of ADNL TCP, developed using [Tokio](https://tokio.rs/).

> **Warning**:  
> This project was never intended for production use; rather, it was designed as a learning experience for working with [Tokio](https://tokio.rs/) and gaining a deeper understanding of the [TON](https://ton.org) protocols.

If you are seeking a more mature, production-ready version with robust support, I recommend checking out [everscale-network/adnl](https://github.com/broxus/everscale-network/tree/master/src/adnl).  
If you are interested in learning more about programming with [Tokio](https://tokio.rs/), you can explore [tokio-rs/mini-redis](https://github.com/tokio-rs/mini-redis).

## Usage

```rust
use adnl_tcp::Client;

#[tokio::main]
async fn main() {
    let mut client = Client::connect(
        "65.21.141.233:30131",
        "wrQaeIFispPfHndEBc0s0fx7GSp8UFFvebnytQQfc6A=",
    )
    .await
    .unwrap();

    let pong = client.ping().await.unwrap();
    println!("{:?}", pong);
}
```

## Credits

A thanks to @xssnick for providing great documentation at [ton-deep-doc/ADNL-TCP-Liteserver](https://github.com/xssnick/ton-deep-doc/blob/master/ADNL-TCP-Liteserver.md) 