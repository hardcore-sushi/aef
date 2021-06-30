use std::{
    convert::TryFrom,
    fmt::{self, Display, Formatter},
    io::{self, Read, Write}
};
use num_enum::TryFromPrimitive;
use chacha20::XChaCha20;
use aes::{Aes256Ctr, cipher::{NewCipher, StreamCipher}};
use hmac::{Hmac, Mac, NewMac};
use rand::{Rng, rngs::OsRng};
use argon2::{Argon2, Version, Algorithm};
use hkdf::Hkdf;
use zeroize::Zeroize;

const SALT_LEN: usize = 64;
const AES_NONCE_LEN: usize = 16;
const XCHACHA20_NONCE_LEN: usize = 24;
const HASH_LEN: usize = 32;
const KEY_LEN: usize = HASH_LEN;

#[derive(Debug, PartialEq, Eq)]
pub struct ArgonParams {
    pub t_cost: u32,
    pub m_cost: u32,
    pub parallelism: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
pub enum CipherAlgorithm {
    AesCtr = 0,
    XChaCha20 = 1,
}

impl CipherAlgorithm {
    fn get_nonce_size(&self) -> usize {
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
    password_salt: [u8; SALT_LEN],
    pub argon2: ArgonParams,
    hkdf_salt: [u8; SALT_LEN],
    nonce: Vec<u8>,
    pub cipher: CipherAlgorithm,
}

impl EncryptionParams {
    fn get_params_len(&self) -> usize {
        SALT_LEN*2 + 4*2 + 2 + self.cipher.get_nonce_size()
    }

    pub fn new(argon2_params: ArgonParams, cipher: CipherAlgorithm) -> EncryptionParams {
        let mut password_salt = [0; SALT_LEN];
        OsRng.fill(&mut password_salt);
        let mut hkdf_salt = [0; SALT_LEN];
        OsRng.fill(&mut hkdf_salt); 
        let mut nonce = vec![0; cipher.get_nonce_size()];
        OsRng.fill(&mut nonce[..]);
        EncryptionParams {
            password_salt,
            argon2: argon2_params,
            hkdf_salt,
            nonce,
            cipher,
        }
    }
    pub fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&self.password_salt)?;
        writer.write_all(&self.argon2.t_cost.to_be_bytes())?;
        writer.write_all(&self.argon2.m_cost.to_be_bytes())?;
        writer.write_all(&self.argon2.parallelism.to_be_bytes())?;
        writer.write_all(&self.hkdf_salt)?;
        writer.write_all(&(self.cipher as u8).to_be_bytes())?;
        writer.write_all(&self.nonce)?;
        Ok(())
    }
    pub fn read<R: Read>(reader: &mut R) -> io::Result<Option<Self>> {
        let mut password_salt = [0; SALT_LEN];
        reader.read_exact(&mut password_salt)?;
        let mut t_cost = [0; 4];
        reader.read_exact(&mut t_cost)?;
        let mut m_cost = [0; 4];
        reader.read_exact(&mut m_cost)?;
        let mut parallelism = [0; 1];
        reader.read_exact(&mut parallelism)?;
        let mut hkdf_salt = [0; SALT_LEN];
        reader.read_exact(&mut hkdf_salt)?;
        let mut cipher_buff = [0; 1];
        reader.read_exact(&mut cipher_buff)?;
        match CipherAlgorithm::try_from(cipher_buff[0]) {
            Ok(cipher) => {
                let mut nonce = vec![0; cipher.get_nonce_size()];
                reader.read_exact(&mut nonce)?;

                let argon2_params = ArgonParams {
                    t_cost: u32::from_be_bytes(t_cost),
                    m_cost: u32::from_be_bytes(m_cost),
                    parallelism: u8::from_be_bytes(parallelism),
                };

                Ok(Some(EncryptionParams {
                    password_salt,
                    argon2: argon2_params,
                    hkdf_salt,
                    nonce,
                    cipher,
                }))
            }
            Err(_) => Ok(None)
        }
    }
}

pub struct DobyCipher {
    cipher: Box<dyn StreamCipher>,
    hmac: Hmac<blake3::Hasher>,
    buffer: Vec<u8>,
}

impl DobyCipher {
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

        let mut encoded_params = Vec::with_capacity(params.get_params_len());
        params.write(&mut encoded_params).unwrap();
        let mut hmac = Hmac::new_from_slice(&authentication_key).unwrap();
        hmac.update(&encoded_params);

        Ok(Self {
            cipher: match params.cipher {
                CipherAlgorithm::AesCtr => Box::new(Aes256Ctr::new_from_slices(&encryption_key, &params.nonce).unwrap()),
                CipherAlgorithm::XChaCha20 => Box::new(XChaCha20::new_from_slices(&encryption_key, &params.nonce).unwrap()),
            },
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

        assert_eq!(params.get_params_len(), 162);

        let mut buff = Vec::with_capacity(162);
        params.write(&mut buff).unwrap();
        assert_eq!(buff[..64], params.password_salt);
        assert_eq!(buff[64..68], vec![0, 0, 0, 0x01]); //t_cost
        assert_eq!(buff[68..72], vec![0, 0, 0, 0x08]); //m_cost
        assert_eq!(buff[72], 0x01); //parallelism
        assert_eq!(buff[73..137], params.hkdf_salt);
        assert_eq!(buff[137], CipherAlgorithm::XChaCha20 as u8);
        assert_eq!(buff[138..], params.nonce);

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
        let password = b"I like spaghetti";
        let plaintext = b"but I love so much to listen to HARDCORE music on big subwoofer";
        let mut buff: [u8; 63] = *plaintext;
        let mut vec = Vec::with_capacity(buff.len()+HASH_LEN);

        let mut enc_cipher = DobyCipher::new(password, &params).unwrap();
        enc_cipher.encrypt_chunk(&mut buff, &mut vec).unwrap();
        assert_ne!(buff, *plaintext);
        assert_eq!(buff, vec.as_slice());
        assert_eq!(enc_cipher.write_hmac(&mut vec).unwrap(), HASH_LEN);
        assert_eq!(vec.len(), buff.len()+HASH_LEN);

        let mut dec_cipher = DobyCipher::new(password, &params).unwrap();
        let mut decrypted = vec![0; buff.len()+HASH_LEN];
        let mut n  = dec_cipher.decrypt_chunk(&mut vec.as_slice(), &mut decrypted[..]).unwrap();
        assert_eq!(n, buff.len());
        n = dec_cipher.decrypt_chunk(&mut &vec[n..], &mut decrypted[n..]).unwrap();
        assert_eq!(n, 0);
        assert_eq!(decrypted[..buff.len()], *plaintext);
        assert_eq!(dec_cipher.verify_hmac(), true);
    }
}