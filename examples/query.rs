use adnl_tcp::Client;

#[tokio::main]
async fn main() {
    let mut client = Client::connect(
        "65.21.141.233:30131",
        "wrQaeIFispPfHndEBc0s0fx7GSp8UFFvebnytQQfc6A=",
    )
    .await
    .unwrap();

    let query_lite_get_time = [223, 6, 140, 121, 4, 52, 90, 173, 22, 0, 0, 0];
    let answer = client.query(&query_lite_get_time).await.unwrap();
    println!("{:?}", answer);
}
