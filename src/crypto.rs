use std::io::{self, Read, Write};
use aes::{Aes256Ctr, cipher::{NewCipher, StreamCipher}};
use hmac::{Hmac, Mac, NewMac};
use rand::{Rng, rngs::OsRng};
use argon2::{Argon2, Version, Algorithm};
use hkdf::Hkdf;
use zeroize::Zeroize;

const SALT_LEN: usize = 64;
const NONCE_LEN: usize = 16;
const HASH_LEN: usize = 32;
const KEY_LEN: usize = HASH_LEN;

pub struct ArgonParams {
    pub t_cost: u32,
    pub m_cost: u32,
    pub parallelism: u8,
}

pub struct EncryptionParams {
    password_salt: [u8; SALT_LEN],
    argon2: ArgonParams,
    hkdf_salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
}

impl EncryptionParams {
    const PARAMS_LEN: usize = SALT_LEN*2 + 4*2 + 1 + NONCE_LEN;

    pub fn new(argon2_params: ArgonParams) -> EncryptionParams {
        let mut password_salt = [0; SALT_LEN];
        OsRng.fill(&mut password_salt);
        let mut hkdf_salt = [0; SALT_LEN];
        OsRng.fill(&mut hkdf_salt); 
        let mut nonce = [0; NONCE_LEN];
        OsRng.fill(&mut nonce);
        EncryptionParams {
            password_salt,
            argon2: argon2_params,
            hkdf_salt,
            nonce,
        }
    }
    pub fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&self.password_salt)?;
        writer.write_all(&self.argon2.t_cost.to_be_bytes())?;
        writer.write_all(&self.argon2.m_cost.to_be_bytes())?;
        writer.write_all(&self.argon2.parallelism.to_be_bytes())?;
        writer.write_all(&self.hkdf_salt)?;
        writer.write_all(&self.nonce)?;
        Ok(())
    }
    pub fn read<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut password_salt = [0; SALT_LEN];
        reader.read_exact(&mut password_salt)?;
        let mut t_cost_buf = [0; 4];
        reader.read_exact(&mut t_cost_buf)?;
        let mut m_cost_buf = [0; 4];
        reader.read_exact(&mut m_cost_buf)?;
        let mut parallelism_buf = [0; 1];
        reader.read_exact(&mut parallelism_buf)?;
        let mut hkdf_salt = [0; SALT_LEN];
        reader.read_exact(&mut hkdf_salt)?;
        let mut nonce = [0; NONCE_LEN];
        reader.read_exact(&mut nonce)?;
    
        let argon2_params = ArgonParams {
            t_cost: u32::from_be_bytes(t_cost_buf),
            m_cost: u32::from_be_bytes(m_cost_buf),
            parallelism: u8::from_be_bytes(parallelism_buf),
        };
    
        Ok(EncryptionParams {
            password_salt,
            argon2: argon2_params,
            hkdf_salt,
            nonce,
        })
    }
}

pub struct Cipher {
    cipher: Aes256Ctr,
    hmac: Hmac<blake3::Hasher>,
    buffer: Vec<u8>,
}

impl Cipher {
    pub fn new(password: &[u8], params: &EncryptionParams) -> Result<Self, argon2::Error> {

        let argon = Argon2::new(None, params.argon2.t_cost, params.argon2.m_cost, params.argon2.parallelism.into(), Version::V0x13)?;
        let mut master_key = [0; KEY_LEN];
        argon.hash_password_into(Algorithm::Argon2id, password, &params.password_salt, &[], &mut master_key)?;

        let hkdf = Hkdf::<blake3::Hasher>::new(Some(&params.hkdf_salt), &master_key);
        let mut encryption_key = [0; KEY_LEN];
        hkdf.expand(b"doby_encryption_key", &mut encryption_key).unwrap();
        let mut authentication_key = [0; KEY_LEN];
        hkdf.expand(b"doby_authentication_key", &mut authentication_key).unwrap();
        master_key.zeroize();

        let mut encoded_params = Vec::with_capacity(EncryptionParams::PARAMS_LEN);
        params.write(&mut encoded_params).unwrap();
        let mut hmac = Hmac::new_from_slice(&authentication_key).unwrap();
        hmac.update(&encoded_params);

        Ok(Cipher {
            cipher: Aes256Ctr::new_from_slices(&encryption_key, &params.nonce).unwrap(),
            hmac,
            buffer: Vec::new(),
        })
    }

    pub fn encrypt_chunk<W: Write>(&mut self, buff: &mut [u8], writer: &mut W) -> io::Result<()> {
        self.cipher.apply_keystream(buff);
        self.hmac.update(buff);
        writer.write_all(buff)
    }

    pub fn write_hmac<W: Write>(self, writer: &mut W) -> io::Result<usize> {
        let tag = self.hmac.finalize().into_bytes();
        writer.write(&tag)
    }

    pub fn decrypt_chunk<R: Read>(&mut self, reader: &mut R, buff: &mut [u8]) -> io::Result<usize> {
        let buffer_len = self.buffer.len();
        buff[..buffer_len].clone_from_slice(&self.buffer);
        let read = reader.read(&mut buff[buffer_len..])?;

        self.buffer.clear();
        let n = if buffer_len + read >= HASH_LEN {
            buffer_len + read - HASH_LEN
        } else {
            0
        };
        self.buffer.extend_from_slice(&buff[n..buffer_len+read]);
        
        self.hmac.update(&buff[..n]);
        self.cipher.apply_keystream(&mut buff[..n]);
        Ok(n)
    }

    pub fn verify_hmac(self) -> bool {
        self.hmac.verify(&self.buffer).is_ok()
    }
}