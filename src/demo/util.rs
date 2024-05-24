use tokio::time::{self, Duration};
// use nu_ansi_term::Color::LightPurple;

#[macro_export]
macro_rules! paint_broadcast {
    ($e:expr) => {
        nu_ansi_term::Color::LightGreen.paint(format!("{}", $e)).to_string()
    };
}

#[macro_export]
macro_rules! paint_request {
    ($e:expr) => {
        nu_ansi_term::Color::LightPurple.paint(format!("{}", $e)).to_string()
    };
}

#[macro_export]
macro_rules! paint_response {
    ($e:expr) => {
        nu_ansi_term::Color::LightBlue.paint(format!("{}", $e)).to_string()
    };
}

pub async fn sleep(seconds: f64) {
    time::sleep(Duration::from_secs_f64(seconds)).await;
}

pub async fn latency() {
    // Random duration from 100..2000 ms

    // let duration = 0.1 + 1.9 * rand::random::<f64>();
    // sleep(duration).await;
}

pub fn handle_ctrl_c() {
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.unwrap();
        println!("\nCtrl-C received, stopping...");
        std::process::exit(0);
    });
}

pub fn chapter_title(title: &str) {
    println!();
    println!("===== {} =====", title);
    println!();
}
