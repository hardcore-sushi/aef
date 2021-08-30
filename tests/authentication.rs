use rand::Rng;
use doby::{
    crypto::{
        ArgonParams,
        CipherAlgorithm,
        EncryptionParams,
        DobyCipher,
    },
    encrypt,
    decrypt,
};

fn different_elements<T: Eq>(v1: &Vec<T>, v2: &Vec<T>) -> usize {
    assert_eq!(v1.len(), v2.len());
    v1.into_iter().enumerate().filter(|x| v2[x.0] != *x.1).count()
}

#[test]
fn authentication() {
    const BLOCK_SIZE: usize = 65536;
    const PLAINTEXT: &[u8; 13] = b"the plaintext";
    const CIPHERTEXT_SIZE: usize = PLAINTEXT.len()+142;
    const PASSWORD: &str = "the password";
    let params = EncryptionParams::new(ArgonParams {
        t_cost: 1,
        m_cost: 8,
        parallelism: 1,
    }, CipherAlgorithm::AesCtr);

    let encrypter = DobyCipher::new(PASSWORD.into(), &params).unwrap();
    let mut ciphertext = Vec::with_capacity(CIPHERTEXT_SIZE);
    encrypt(&mut &PLAINTEXT[..], &mut ciphertext, &params, encrypter, BLOCK_SIZE, None).unwrap();
    assert_eq!(ciphertext.len(), CIPHERTEXT_SIZE);

    for i in 0..ciphertext.len() {
        let mut compromised = ciphertext.clone();
        while compromised[i] == ciphertext[i] {
            compromised[i] = rand::thread_rng().gen();
        }
        assert_eq!(different_elements(&compromised, &ciphertext), 1);
        let decrypter = DobyCipher::new(PASSWORD.into(), &params).unwrap();
        let mut decrypted = Vec::with_capacity(PLAINTEXT.len());
        let verified = decrypt(&mut &compromised[..], &mut decrypted, decrypter, BLOCK_SIZE).unwrap();
        assert_eq!(verified, false);
    }

    let decrypter = DobyCipher::new(PASSWORD.into(), &params).unwrap();
    let mut decrypted = Vec::with_capacity(PLAINTEXT.len());
    let verified = decrypt(&mut &ciphertext[4+params.get_params_len()..], &mut decrypted, decrypter, BLOCK_SIZE).unwrap();
    assert_eq!(decrypted, PLAINTEXT);
    assert_eq!(verified, true);
}