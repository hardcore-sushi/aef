use std::{env, fs::File, io::{self, Read}};
use doby::{MAGIC_BYTES, crypto::EncryptionParams};

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    let mut file = File::open(&args[1])?;

    let mut magic_bytes = vec![0; MAGIC_BYTES.len()];
    file.read(&mut magic_bytes)?;
    if magic_bytes == MAGIC_BYTES {
        match EncryptionParams::read(&mut file)? {
            Some(params) => {
                println!("Argon2 time cost: {}", params.argon2.t_cost());
                println!("Argon2 memory cost: {}KB", params.argon2.m_cost());
                println!("Argon2 parallelism cost: {}", params.argon2.p_cost());
                println!("Encryption cihpher: {}", params.cipher);
            }
            None => eprintln!("Invalid parameters")
        }
    } else {
        eprintln!("Doby format not recognized.");
    }
    Ok(())
}