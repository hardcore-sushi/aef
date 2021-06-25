pub mod cli;
pub mod crypto;

use std::io::{self, Read, Write};
use crypto::{Cipher, EncryptionParams};

pub const MAGIC_BYTES: &[u8; 4] = b"DOBY";

pub fn encrypt<R: Read, W: Write>(reader: &mut R, writer: &mut W, params: &EncryptionParams, mut cipher: Cipher, block_size: usize, already_read: Option<Vec<u8>>) -> io::Result<()> {
    writer.write_all(MAGIC_BYTES)?;
    params.write(writer)?;
    let mut buff = vec![0; block_size];
    let mut n = 1;
    if let Some(already_read) = already_read {
        buff[..already_read.len()].clone_from_slice(&already_read);
        n = reader.read(&mut buff[already_read.len()..])?;
        cipher.encrypt_chunk(&mut buff[..n+already_read.len()], writer)?;
    }
    if n > 0 {
        loop {
            n = reader.read(&mut buff)?;
            if n == 0 {
                break;
            } else {
                cipher.encrypt_chunk(&mut buff[..n], writer)?;
            }
        }
        cipher.write_hmac(writer)?;
    }
    Ok(())
}

pub fn decrypt<R: Read, W: Write>(reader: &mut R, writer: &mut W, mut cipher: Cipher, block_size: usize) -> io::Result<bool> {
    let mut buff = vec![0; block_size];
    loop {
        let n = cipher.decrypt_chunk(reader, &mut buff)?;
        if n == 0 {
            break;
        } else {
           writer.write(&buff[..n])?;
        }
    }
    Ok(cipher.verify_hmac())
}