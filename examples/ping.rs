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
