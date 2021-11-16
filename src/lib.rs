pub mod cli;
pub mod crypto;

use std::{fmt::Display, fs::OpenOptions, io::{self, BufWriter, Read, Write}, path::Path};
use crypto::{DobyCipher, EncryptionParams};
use zeroize::Zeroize;

pub const MAGIC_BYTES: &[u8; 4] = b"DOBY";

pub struct WrappedPassword(Option<String>);

impl WrappedPassword {
    pub fn get(self, ask_confirm: bool) -> Option<String> {
        self.0.or_else(|| {
            let mut password = rpassword::read_password_from_tty(Some("Password: ")).ok()?;
            if ask_confirm {
                let mut password_confirm = rpassword::read_password_from_tty(Some("Password (confirm): ")).ok()?;
                if password == password_confirm {
                    password_confirm.zeroize();
                    Some(password)
                } else {
                    password.zeroize();
                    password_confirm.zeroize();
                    eprintln!("Error: passwords don't match");
                    None
                }
            } else {
                Some(password)
            }
        })
    }
}

impl From<Option<&str>> for WrappedPassword {
    fn from(s: Option<&str>) -> Self {
        Self(s.map(String::from))
    }
}
pub enum WrappedWriter<P: AsRef<Path>> {
    PATH {
        path: P
    },
    WRITER {
        writer: Box<dyn Write>
    }
}

impl<P: AsRef<Path> + Display> WrappedWriter<P> {
    fn from_path(path: P) -> Self {
        Self::PATH { path }
    }

    fn from_writer<T: 'static + Write>(writer: T) -> Self {
        Self::WRITER { writer: Box::new(writer) }
    }

    pub fn into_buf_writer(self) -> Option<BufWriter<Box<dyn Write>>> {
        Some(BufWriter::new(match self {
            Self::PATH { path } => Box::new(
                OpenOptions::new().write(true).create(true).truncate(true).open(path.as_ref())
                    .map_err(|e| eprintln!("{}: {}", path, e))
                    .ok()?
            ) as Box<dyn Write>,
            Self::WRITER { writer } => writer,
        }))
    }
}

pub fn encrypt<R: Read, W: Write>(reader: &mut R, writer: &mut W, params: &EncryptionParams, mut cipher: DobyCipher, block_size: usize, already_read: Option<&[u8]>) -> io::Result<()> {
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
    }
    cipher.write_hmac(writer)?;
    Ok(())
}

pub fn decrypt<R: Read, W: Write>(reader: &mut R, writer: &mut W, mut cipher: DobyCipher, block_size: usize) -> io::Result<bool> {
    let mut buff = vec![0; block_size];
    loop {
        let n = cipher.decrypt_chunk(reader, &mut buff)?;
        if n == 0 {
            break;
        } else {
           writer.write_all(&buff[..n])?;
        }
    }
    Ok(cipher.verify_hmac())
}