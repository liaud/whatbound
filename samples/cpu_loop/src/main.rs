use std::hint::black_box;

fn main() {
    let numbers = vec![0, 1, 2, 3, 4, 5, 6, 7];
    loop {
        black_box({
            let _ = numbers.binary_search(&2);
        });
    }
}
