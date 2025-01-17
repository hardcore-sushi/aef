use std::{convert::TryFrom, fmt::{self, Display, Formatter}, io::{self, Read, Write}};
use blake2::{Blake2b, VarBlake2b, digest::{Update, VariableOutput}};
use num_enum::TryFromPrimitive;
use chacha20::XChaCha20;
use aes::{Aes256Ctr, cipher::{NewCipher, StreamCipher}};
use subtle::ConstantTimeEq;
use rand::{Rng, rngs::OsRng};
use argon2::{Argon2, Version, Algorithm};
use hkdf::Hkdf;
use zeroize::Zeroize;

pub const SALT_LEN: usize = 64;
const AES_NONCE_LEN: usize = 16;
const XCHACHA20_NONCE_LEN: usize = 24;
pub const HMAC_LEN: usize = 32;
const KEY_LEN: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
pub enum CipherAlgorithm {
    AesCtr = 0,
    XChaCha20 = 1,
}

impl CipherAlgorithm {
    pub fn get_nonce_size(&self) -> usize {
        match self {
            CipherAlgorithm::AesCtr => AES_NONCE_LEN,
            CipherAlgorithm::XChaCha20 => XCHACHA20_NONCE_LEN,
        }
    }
}

impl Display for CipherAlgorithm {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            CipherAlgorithm::AesCtr => "AES-CTR",
            CipherAlgorithm::XChaCha20 => "XChaCha20",
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct EncryptionParams {
    salt: [u8; SALT_LEN],
    pub argon2: argon2::Params,
    pub cipher: CipherAlgorithm,
}

impl EncryptionParams {
    pub const LEN: usize = SALT_LEN + 4*3 + 1;

    pub fn new(argon2_params: argon2::Params, cipher: CipherAlgorithm) -> EncryptionParams {
        let mut salt = [0; SALT_LEN];
        OsRng.fill(&mut salt);
        EncryptionParams {
            salt,
            argon2: argon2_params,
            cipher,
        }
    }

    pub fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&self.salt)?;
        writer.write_all(&self.argon2.t_cost().to_be_bytes())?;
        writer.write_all(&self.argon2.m_cost().to_be_bytes())?;
        writer.write_all(&self.argon2.p_cost().to_be_bytes())?;
        writer.write_all(&(self.cipher as u8).to_be_bytes())?;
        Ok(())
    }

    pub fn read<R: Read>(reader: &mut R) -> io::Result<Option<Self>> {
        let mut salt = [0; SALT_LEN];
        reader.read_exact(&mut salt)?;
        let mut t_cost = [0; 4];
        reader.read_exact(&mut t_cost)?;
        let mut m_cost = [0; 4];
        reader.read_exact(&mut m_cost)?;
        let mut p_cost = [0; 4];
        reader.read_exact(&mut p_cost)?;
        let mut cipher_buff = [0; 1];
        reader.read_exact(&mut cipher_buff)?;
        if let Ok(cipher) = CipherAlgorithm::try_from(cipher_buff[0]) {
            if let Ok(argon2_params) = argon2::Params::new(
                u32::from_be_bytes(m_cost),
                u32::from_be_bytes(t_cost),
                u32::from_be_bytes(p_cost),
                None
            ) {
                return Ok(Some(EncryptionParams {
                    salt,
                    argon2: argon2_params,
                    cipher,
                }));
            }
        }
        Ok(None)
    }
}

pub struct DobyCipher {
    cipher: Box<dyn StreamCipher>,
    hasher: VarBlake2b,
    buffer: Vec<u8>,
}

impl DobyCipher {
    pub fn new(password: &[u8], params: &EncryptionParams) -> Self {
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params.argon2.clone());
        let mut master_key = [0; KEY_LEN];
        argon2.hash_password_into(password, &params.salt, &mut master_key).unwrap();
        let hkdf = Hkdf::<Blake2b>::new(Some(&params.salt), &master_key);
        master_key.zeroize();
        let mut nonce = vec![0; params.cipher.get_nonce_size()];
        hkdf.expand(b"doby_nonce", &mut nonce).unwrap();
        let mut encryption_key = [0; KEY_LEN];
        hkdf.expand(b"doby_encryption_key", &mut encryption_key).unwrap();
        let mut authentication_key = [0; KEY_LEN];
        hkdf.expand(b"doby_authentication_key", &mut authentication_key).unwrap();

        let mut encoded_params = Vec::with_capacity(EncryptionParams::LEN);
        params.write(&mut encoded_params).unwrap();
        let mut hasher = VarBlake2b::new_keyed(&authentication_key, HMAC_LEN);
        authentication_key.zeroize();
        hasher.update(&encoded_params);

        let cipher: Box<dyn StreamCipher> = match params.cipher {
            CipherAlgorithm::AesCtr => Box::new(Aes256Ctr::new_from_slices(&encryption_key, &nonce).unwrap()),
            CipherAlgorithm::XChaCha20 => Box::new(XChaCha20::new_from_slices(&encryption_key, &nonce).unwrap()),
        };
        encryption_key.zeroize();

        Self {
            cipher,
            hasher,
            buffer: Vec::new(),
        }
    }

    pub fn encrypt_chunk<W: Write>(&mut self, buff: &mut [u8], writer: &mut W) -> io::Result<()> {
        self.cipher.apply_keystream(buff);
        self.hasher.update(&buff);
        writer.write_all(buff)
    }

    pub fn write_hmac<W: Write>(self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&self.hasher.finalize_boxed())
    }

    //buff size must be > to HASH_LEN
    pub fn decrypt_chunk<R: Read>(&mut self, reader: &mut R, buff: &mut [u8]) -> io::Result<usize> {
        let buffer_len = self.buffer.len();
        buff[..buffer_len].clone_from_slice(&self.buffer);
        let read = reader.read(&mut buff[buffer_len..])?;

        let n = if buffer_len + read >= HMAC_LEN {
            self.buffer.clear();
            buffer_len + read - HMAC_LEN
        } else {
            0
        };
        self.buffer.extend_from_slice(&buff[n..buffer_len+read]);
        
        self.hasher.update(&buff[..n]);
        self.cipher.apply_keystream(&mut buff[..n]);
        Ok(n)
    }

    pub fn verify_hmac(self) -> bool {
        self.hasher.finalize_boxed().ct_eq(&self.buffer).into()
    }
}

#[cfg(test)]
mod tests {
    use super::{CipherAlgorithm, EncryptionParams, DobyCipher, HMAC_LEN};
    #[test]
    fn encryption_params() {
        let params = EncryptionParams::new(
            argon2::Params::new(8, 1, 1, None).unwrap(),
            CipherAlgorithm::XChaCha20
        );

        assert_eq!(EncryptionParams::LEN, 77);

        let mut buff = Vec::with_capacity(74);
        params.write(&mut buff).unwrap();
        assert_eq!(buff[..64], params.salt);
        assert_eq!(buff[64..68], vec![0, 0, 0, 0x01]); //t_cost
        assert_eq!(buff[68..72], vec![0, 0, 0, 0x08]); //m_cost
        assert_eq!(buff[72..76], vec![0, 0, 0, 0x01]); //p_cost
        assert_eq!(buff[76], CipherAlgorithm::XChaCha20 as u8);

        let new_params = EncryptionParams::read(&mut buff.as_slice()).unwrap().unwrap();
        assert_eq!(new_params, params);
    }

    #[test]
    fn doby_cipher() {
        let params = EncryptionParams::new(
            argon2::Params::new(8, 1, 1, None).unwrap(),
            CipherAlgorithm::AesCtr
        );
        let password = "I like spaghetti";
        let plaintext = b"but I love so much to listen to HARDCORE music on big subwoofer";
        let mut buff: [u8; 63] = *plaintext;
        let mut vec = Vec::with_capacity(buff.len()+HMAC_LEN);

        let mut enc_cipher = DobyCipher::new(password.as_bytes(), &params);
        enc_cipher.encrypt_chunk(&mut buff, &mut vec).unwrap();
        assert_ne!(buff, *plaintext);
        assert_eq!(buff, vec.as_slice());
        assert!(enc_cipher.write_hmac(&mut vec).is_ok());
        assert_eq!(vec.len(), buff.len()+HMAC_LEN);

        let mut dec_cipher = DobyCipher::new(password.as_bytes(), &params);
        let mut decrypted = vec![0; buff.len()+HMAC_LEN];
        let mut n  = dec_cipher.decrypt_chunk(&mut vec.as_slice(), &mut decrypted[..]).unwrap();
        assert_eq!(n, buff.len());
        n = dec_cipher.decrypt_chunk(&mut &vec[n..], &mut decrypted[n..]).unwrap();
        assert_eq!(n, 0);
        assert_eq!(decrypted[..buff.len()], *plaintext);
        assert_eq!(dec_cipher.verify_hmac(), true);
    }
}