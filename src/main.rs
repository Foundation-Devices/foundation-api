#[cfg(feature = "tokio")]
mod demo;

#[cfg(feature = "tokio")]
#[tokio::main]
async fn main() {
    use demo::*;

    // Gracefully handle Ctrl-C
    handle_ctrl_c();

    chapter_title(
        "🤝 Envoy and Passport pair using Discovery QR code and Bluetooth pairing \
         request/response.",
    );

    // Instantiate the channels that connect the devices
    let screen_peers = ScreenPeers::new(PASSPORT_PREFIX, ENVOY_PREFIX);
    let bluetooth_peers = BluetoothPeers::new();

    // Instantiate the two devices
    let passport = Passport::new(
        screen_peers.screen().clone(),
        bluetooth_peers.peer1().clone(),
    );
    let envoy = Envoy::new(
        screen_peers.camera().clone(),
        bluetooth_peers.peer2().clone(),
    );

    // Start the devices
    let passport_task = passport.boot();
    let envoy_task = envoy.boot();

    // Wait for them to finish
    passport_task.await.unwrap();
    envoy_task.await.unwrap();

    chapter_title("🏁 All done");
}

#[cfg(not(feature = "tokio"))]
fn main() {
    println!("Please enable the 'tokio' feature to run this example.");
}
