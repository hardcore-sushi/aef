pub mod cli;
pub mod crypto;

use std::{fs::File, path::Path, io::{self, Read, Write}};
use crypto::{DobyCipher, EncryptionParams};
use zeroize::Zeroize;

pub const MAGIC_BYTES: &[u8; 4] = b"DOBY";

pub struct Password(Option<String>);

impl Password {
    fn unwrap_or_ask(self) -> String {
        self.0.unwrap_or_else(|| rpassword::read_password_from_tty(Some("Password: ")).unwrap())
    }
}

impl From<Option<&str>> for Password {
    fn from(s: Option<&str>) -> Self {
        Self(s.map(|s| String::from(s)))
    }
}

impl From<&str> for Password {
    fn from(s: &str) -> Self {
        Some(s).into()
    }
}

impl Zeroize for Password {
    fn zeroize(&mut self) {
        self.0.zeroize()
    }
}

pub struct LazyWriter<P: AsRef<Path>> {
    path: Option<P>,
    writer: Option<Box<dyn Write>>,
}

impl<P: AsRef<Path>> LazyWriter<P> {
    fn from_path(path: P) -> Self {
        Self {
            path: Some(path),
            writer: None,
        }
    }
    fn from_writer<T: 'static + Write>(writer: T) -> Self {
        Self {
            path: None,
            writer: Some(Box::new(writer)),
        }
    }
}

impl<P: AsRef<Path>> Write for LazyWriter<P> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.writer.is_none() {
            self.writer = Some(Box::new(File::create(self.path.as_ref().unwrap()).unwrap()));
        }
        self.writer.as_mut().unwrap().write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.as_mut().unwrap().flush()
    }
}

pub fn encrypt<R: Read, W: Write>(reader: &mut R, writer: &mut W, params: &EncryptionParams, mut cipher: DobyCipher, block_size: usize, already_read: Option<Vec<u8>>) -> io::Result<()> {
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

pub fn decrypt<R: Read, W: Write>(reader: &mut R, writer: &mut W, mut cipher: DobyCipher, block_size: usize) -> io::Result<bool> {
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