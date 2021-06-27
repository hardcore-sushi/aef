use std::{
    io::{self, BufWriter, BufReader, Write, Seek, SeekFrom},
    time::Instant,
    env,
    fs::{File, OpenOptions}
};
use doby::{
    encrypt, decrypt,
    crypto::{ArgonParams, EncryptionParams, CipherAlgorithm, DobyCipher}
};

const MAX_BLOCK_SIZE: usize = 1_073_741_824; //1GB
const PASSWORD: &[u8] = b"HARDCORE music is the best music of all time";

fn set_if_better(best_time: &mut Option<u128>, time: u128, best_block_size: &mut Option<usize>, block_size: usize) {
    let mut better = true;
    if let Some(best_time) = best_time {
        better = time < *best_time;
    }
    if better {
        *best_time = Some(time);
        *best_block_size = Some(block_size);
    }
}

fn reset<I: Seek>(i: &mut I) -> io::Result<u64> {
    i.seek(SeekFrom::Start(0))
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();

    let input = File::open(&args[1])?;
    let output = OpenOptions::new().create(true).truncate(true).write(true).open(&args[2])?;

    let params = EncryptionParams::new(ArgonParams{
        t_cost: 1,
        m_cost: 8,
        parallelism: 1,
    }, CipherAlgorithm::AesCtr);

    let mut best_encrypt_time = None;
    let mut best_encrypt_block_size = None;
    let mut best_decrypt_time = None;
    let mut best_decrypt_block_size = None;

    let mut block_size = 1024;
    while block_size <= MAX_BLOCK_SIZE {
        let mut reader = BufReader::with_capacity(block_size, &input);
        let mut writer = BufWriter::with_capacity(block_size, &output);

        let cipher = DobyCipher::new(PASSWORD, &params).unwrap();
        let t_encrypt = Instant::now();
        encrypt(&mut reader, &mut writer, &params, cipher, block_size, None)?;
        writer.flush()?;
        let encrypt_time = t_encrypt.elapsed().as_millis();
        println!("Encrypted in {}ms with block size of {}B", encrypt_time, block_size);
        set_if_better(&mut best_encrypt_time, encrypt_time, &mut best_encrypt_block_size, block_size);
        reset(&mut reader)?;
        reset(&mut writer)?;

        let cipher = DobyCipher::new(PASSWORD, &params).unwrap();
        let t_decrypt = Instant::now();
        decrypt(&mut reader, &mut writer, cipher, block_size)?;
        writer.flush()?;
        let decrypt_time = t_decrypt.elapsed().as_millis();
        println!("Decrypted in {}ms with block size of {}B", decrypt_time, block_size);
        set_if_better(&mut best_decrypt_time, decrypt_time, &mut best_decrypt_block_size, block_size);
        reset(&mut reader)?;
        reset(&mut writer)?;

        block_size *= 2;
    }

    println!("
    Best block size for encryption: {}B
    Time: {}ms
    
    Best block size for decryption: {}B
    Time: {}ms
    ", best_encrypt_block_size.unwrap(), best_encrypt_time.unwrap(), best_decrypt_block_size.unwrap(), best_decrypt_time.unwrap());

    Ok(())
}