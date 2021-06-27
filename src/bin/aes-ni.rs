cpufeatures::new!(aes_ni, "aes");

fn main() {
    println!("AES-NI is {}supported on this device.", if aes_ni::get() {
        ""
    } else {
        "NOT "
    });
}