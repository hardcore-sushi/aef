use std::{process, io::{BufReader, Read}};
use doby::{
    cli,
    crypto::{EncryptionParams, DobyCipher},
    MAGIC_BYTES,
    decrypt,
    encrypt,
};
use zeroize::Zeroize;

fn run() -> bool {
    let mut success = false;
    if let Some(result) = cli::parse() {
        if let Some(cli_args) = result.cli_args {
            let mut reader = BufReader::new(cli_args.reader);

            let mut magic_bytes = vec![0; MAGIC_BYTES.len()];
            match reader.read(&mut magic_bytes) {
                Ok(n) => {
                    if magic_bytes == MAGIC_BYTES && !cli_args.force_encrypt { //we probably want to decrypt
                        match EncryptionParams::read(&mut reader) {
                            Ok(params) => {
                                if let Some(params) = params {
                                    if let Some(mut password) = cli_args.password.get(false) {
                                        if let Some(mut writer) = cli_args.writer.into_buf_writer() {
                                            let cipher = DobyCipher::new(password.as_bytes(), &params);
                                            password.zeroize();
                                            match decrypt(&mut reader, &mut writer, cipher, cli_args.block_size) {
                                                Ok(verified) => {
                                                    if verified {
                                                        success = true
                                                    } else {
                                                        eprintln!("Warning: HMAC verification failed !\nEither your password is incorrect or the ciphertext has been corrupted.\nBe careful, the data could have been altered by an attacker.");
                                                    }
                                                }
                                                Err(e) => eprintln!("I/O error while decrypting: {}", e)
                                            }
                                        } else {
                                            password.zeroize();
                                        }
                                    }
                                } else {
                                    eprintln!("Error: invalid encryption parameters")
                                }
                            }
                            Err(e) => eprintln!("I/O error while reading headers: {}", e)
                        }
                    } else { //otherwise, encrypt
                        let params = EncryptionParams::new(cli_args.argon2_params, cli_args.cipher);
                        if let Some(mut password) = cli_args.password.get(true) {
                            if let Some(mut writer) = cli_args.writer.into_buf_writer() {
                                let cipher = DobyCipher::new(password.as_bytes(), &params);
                                password.zeroize();
                                match encrypt(
                                    &mut reader,
                                    &mut writer,
                                    &params,
                                    cipher,
                                    cli_args.block_size,
                                    Some(&magic_bytes[..n])
                                ) {
                                    Ok(_) => success = true,
                                    Err(e) => eprintln!("I/O error while encrypting: {}", e)
                                }
                            } else {
                                password.zeroize();
                            }
                        }
                    }
                }
                Err(e) => eprintln!("I/O error while reading magic bytes: {}", e),
            }
        } else {
            success = !result.error;
        }
    }
    success
}

fn main() {
    process::exit(if run() {
        0
    } else {
        1
    });
}
