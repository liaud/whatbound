use std::time::Duration;

fn main() {
    loop {
        println!("sleeping...");
        std::thread::sleep(Duration::from_secs(2));
    }
}
