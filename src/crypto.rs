use std::{convert::{TryFrom, TryInto}, fmt::{self, Display, Formatter}, io::{self, Read, Write}};
use num_enum::TryFromPrimitive;
use chacha20::XChaCha20;
use aes::{Aes256Ctr, cipher::{NewCipher, StreamCipher}};
use hmac::{Hmac, Mac, NewMac};
use rand::{Rng, rngs::OsRng};
use argon2::{Argon2, Version, Algorithm};
use hkdf::Hkdf;
use zeroize::Zeroize;
use crate::Password;

pub const SALT_LEN: usize = 64;
const AES_NONCE_LEN: usize = 16;
const XCHACHA20_NONCE_LEN: usize = 24;
pub const HASH_LEN: usize = 64;
const KEY_LEN: usize = 32;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct ArgonParams {
    pub t_cost: u32,
    pub m_cost: u32,
    pub parallelism: u8,
}

impl TryFrom<ArgonParams> for argon2::Params {
    type Error = argon2::Error;
    fn try_from(params: ArgonParams) -> Result<Self, Self::Error> {
        argon2::Params::new(params.m_cost, params.t_cost, params.parallelism.into(), None)
    }
}

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
    pub argon2: ArgonParams,
    pub cipher: CipherAlgorithm,
}

impl EncryptionParams {
    pub const LEN: usize = SALT_LEN + 4*2 + 2;

    pub fn new(argon2_params: ArgonParams, cipher: CipherAlgorithm) -> EncryptionParams {
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
        writer.write_all(&self.argon2.t_cost.to_be_bytes())?;
        writer.write_all(&self.argon2.m_cost.to_be_bytes())?;
        writer.write_all(&self.argon2.parallelism.to_be_bytes())?;
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
        let mut parallelism = [0; 1];
        reader.read_exact(&mut parallelism)?;
        let mut cipher_buff = [0; 1];
        reader.read_exact(&mut cipher_buff)?;
        match CipherAlgorithm::try_from(cipher_buff[0]) {
            Ok(cipher) => {
                let argon2_params = ArgonParams {
                    t_cost: u32::from_be_bytes(t_cost),
                    m_cost: u32::from_be_bytes(m_cost),
                    parallelism: u8::from_be_bytes(parallelism),
                };

                Ok(Some(EncryptionParams {
                    salt,
                    argon2: argon2_params,
                    cipher,
                }))
            }
            Err(_) => Ok(None)
        }
    }
}

trait ThenZeroize {
    fn zeroize<T: Zeroize>(self, v: T) -> Self;
}

impl<S, E> ThenZeroize for Result<S, E> {
    fn zeroize<T: Zeroize>(self, mut v: T) -> Self {
        v.zeroize();
        self
    }
}

pub struct DobyCipher {
    cipher: Box<dyn StreamCipher>,
    hmac: Hmac<blake2::Blake2b>,
    buffer: Vec<u8>,
}

impl DobyCipher {
    pub fn new(mut password: Password, params: &EncryptionParams) -> Result<Self, argon2::Error> {
        match params.argon2.try_into() {
            Ok(argon2_params) => {
                let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);
                let mut master_key = [0; KEY_LEN];
                let password = password.unwrap_or_ask();
                argon2.hash_password_into(password.as_bytes(), &params.salt, &mut master_key).zeroize(password)?;
                let hkdf = Hkdf::<blake2::Blake2b>::new(Some(&params.salt), &master_key);
                let mut nonce = vec![0; params.cipher.get_nonce_size()];
                hkdf.expand(b"doby_nonce", &mut nonce).unwrap();
                let mut encryption_key = [0; KEY_LEN];
                hkdf.expand(b"doby_encryption_key", &mut encryption_key).unwrap();
                let mut authentication_key = [0; KEY_LEN];
                hkdf.expand(b"doby_authentication_key", &mut authentication_key).unwrap();
                master_key.zeroize();

                let mut encoded_params = Vec::with_capacity(EncryptionParams::LEN);
                params.write(&mut encoded_params).unwrap();
                let mut hmac = Hmac::new_from_slice(&authentication_key).unwrap();
                authentication_key.zeroize();
                hmac.update(&encoded_params);

                let cipher: Box<dyn StreamCipher> = match params.cipher {
                    CipherAlgorithm::AesCtr => Box::new(Aes256Ctr::new_from_slices(&encryption_key, &nonce).unwrap()),
                    CipherAlgorithm::XChaCha20 => Box::new(XChaCha20::new_from_slices(&encryption_key, &nonce).unwrap()),
                };
                encryption_key.zeroize();

                Ok(Self {
                    cipher,
                    hmac,
                    buffer: Vec::new(),
                })
            }
            Err(e) => {
                password.zeroize();
                Err(e)
            }
        }
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

    //buff size must be > to HASH_LEN
    pub fn decrypt_chunk<R: Read>(&mut self, reader: &mut R, buff: &mut [u8]) -> io::Result<usize> {
        let buffer_len = self.buffer.len();
        buff[..buffer_len].clone_from_slice(&self.buffer);
        let read = reader.read(&mut buff[buffer_len..])?;

        let n = if buffer_len + read >= HASH_LEN {
            self.buffer.clear();
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

#[cfg(test)]
mod tests {
    use super::{ArgonParams, CipherAlgorithm, EncryptionParams, DobyCipher, HASH_LEN};
    #[test]
    fn encryption_params() {
        let params = EncryptionParams::new(ArgonParams {
            t_cost: 1,
            m_cost: 8,
            parallelism: 1,
        }, CipherAlgorithm::XChaCha20);

        assert_eq!(EncryptionParams::LEN, 74);

        let mut buff = Vec::with_capacity(74);
        params.write(&mut buff).unwrap();
        assert_eq!(buff[..64], params.salt);
        assert_eq!(buff[64..68], vec![0, 0, 0, 0x01]); //t_cost
        assert_eq!(buff[68..72], vec![0, 0, 0, 0x08]); //m_cost
        assert_eq!(buff[72], 0x01); //parallelism
        assert_eq!(buff[73], CipherAlgorithm::XChaCha20 as u8);

        let new_params = EncryptionParams::read(&mut buff.as_slice()).unwrap().unwrap();
        assert_eq!(new_params, params);
    }

    #[test]
    fn doby_cipher() {
        let params = EncryptionParams::new(ArgonParams {
            t_cost: 1,
            m_cost: 8,
            parallelism: 1,
        }, CipherAlgorithm::AesCtr);
        let password = "I like spaghetti";
        let plaintext = b"but I love so much to listen to HARDCORE music on big subwoofer";
        let mut buff: [u8; 63] = *plaintext;
        let mut vec = Vec::with_capacity(buff.len()+HASH_LEN);

        let mut enc_cipher = DobyCipher::new(password.into(), &params).unwrap();
        enc_cipher.encrypt_chunk(&mut buff, &mut vec).unwrap();
        assert_ne!(buff, *plaintext);
        assert_eq!(buff, vec.as_slice());
        assert_eq!(enc_cipher.write_hmac(&mut vec).unwrap(), HASH_LEN);
        assert_eq!(vec.len(), buff.len()+HASH_LEN);

        let mut dec_cipher = DobyCipher::new(password.into(), &params).unwrap();
        let mut decrypted = vec![0; buff.len()+HASH_LEN];
        let mut n  = dec_cipher.decrypt_chunk(&mut vec.as_slice(), &mut decrypted[..]).unwrap();
        assert_eq!(n, buff.len());
        n = dec_cipher.decrypt_chunk(&mut &vec[n..], &mut decrypted[n..]).unwrap();
        assert_eq!(n, 0);
        assert_eq!(decrypted[..buff.len()], *plaintext);
        assert_eq!(dec_cipher.verify_hmac(), true);
    }
}