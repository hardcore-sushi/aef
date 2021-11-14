use std::{convert::TryInto, fs::{self, File, create_dir}, io::{self, Read, Write}, path::PathBuf};
use assert_cmd::{Command, cargo::{CargoError, cargo_bin}};
use tempfile::TempDir;
use doby::crypto::{CipherAlgorithm, SALT_LEN, HMAC_LEN};

const PLAINTEXT: &[u8] = b"the plaintext";
const PASSWORD: &str = "the password";

fn setup_files<'a>() -> io::Result<(PathBuf, PathBuf, PathBuf)> {
    let tmp_dir = TempDir::new()?;
    let tmp_path = PathBuf::from(tmp_dir.path());
    drop(tmp_dir);
    create_dir(&tmp_path)?;

    let tmp_plaintext = tmp_path.join("plaintext");
    let tmp_ciphertext = tmp_path.join("ciphertext");

    File::create(&tmp_plaintext)?.write_all(PLAINTEXT)?;

    Ok((tmp_path, tmp_plaintext, tmp_ciphertext))
}

fn doby_cmd() -> Result<Command, CargoError> {
    let mut cmd = Command::cargo_bin("doby")?;
    cmd.arg("--password").arg(PASSWORD);
    Ok(cmd)
}

fn bash_cmd() -> Command {
    let mut cmd = Command::new("bash");
    cmd.arg("-c");
    cmd
}

#[test]
fn files() -> io::Result<()> {
    let (tmp_path, tmp_plaintext, tmp_ciphertext) = setup_files()?;

    doby_cmd().unwrap().arg(tmp_plaintext).arg(&tmp_ciphertext).assert().success().stdout("").stderr("");

    let tmp_decrypted = tmp_path.join("decrypted");
    doby_cmd().unwrap().arg(tmp_ciphertext).arg(&tmp_decrypted).assert().success().stdout("").stderr("");

    let mut buff = [0; PLAINTEXT.len()];
    assert_eq!(File::open(tmp_decrypted)?.read(&mut buff)?, PLAINTEXT.len());
    assert_eq!(buff, PLAINTEXT);

    Ok(())
}

#[test]
fn stdout() -> io::Result<()> {
    let (_, tmp_plaintext, tmp_ciphertext) = setup_files()?;
    
    let shell_cmd = format!("{} --password \"{}\" {} > {}", cargo_bin("doby").to_str().unwrap(), PASSWORD, tmp_plaintext.to_str().unwrap(), tmp_ciphertext.to_str().unwrap());
    bash_cmd().arg(shell_cmd).assert().success().stdout("").stderr("");
    
    doby_cmd().unwrap().arg(tmp_ciphertext).assert().success().stdout(PLAINTEXT);

    Ok(())
}

#[test]
fn stdin() -> io::Result<()> {
    let (_, tmp_plaintext, tmp_ciphertext) = setup_files()?;

    let mut shell_cmd = format!("cat {} | {} --password \"{}\" - {}", tmp_plaintext.to_str().unwrap(), cargo_bin("doby").to_str().unwrap(), PASSWORD, tmp_ciphertext.to_str().unwrap());
    bash_cmd().arg(shell_cmd).assert().success().stdout("").stderr("");

    shell_cmd = format!("cat {} | {} --password \"{}\"", tmp_ciphertext.to_str().unwrap(), cargo_bin("doby").to_str().unwrap(), PASSWORD);
    bash_cmd().arg(shell_cmd).assert().success().stdout(PLAINTEXT);

    Ok(())
}

#[test]
fn force_encrypt() -> io::Result<()> {
    let (tmp_path, tmp_plaintext, tmp_ciphertext_1) = setup_files()?;

    doby_cmd().unwrap().arg(tmp_plaintext).arg(&tmp_ciphertext_1).assert().success().stdout("").stderr("");

    let tmp_ciphertext_2 = tmp_path.join("ciphertext_2");
    doby_cmd().unwrap().arg("-f").arg(&tmp_ciphertext_1).arg(&tmp_ciphertext_2).assert().success().stdout("").stderr("");
    let buff_ciphertext_1 = fs::read(tmp_ciphertext_1)?;
    let buff_ciphertext_2 = fs::read(&tmp_ciphertext_2)?;
    assert_ne!(buff_ciphertext_1, buff_ciphertext_2);
    assert_ne!(buff_ciphertext_2, PLAINTEXT);
    assert!(buff_ciphertext_2.len() >= buff_ciphertext_1.len()+113);

    let tmp_decrypted_1 = tmp_path.join("decrypted_1");
    doby_cmd().unwrap().arg(tmp_ciphertext_2).arg(&tmp_decrypted_1).assert().success().stdout("").stderr("");
    let buff_decrypted_1 = fs::read(&tmp_decrypted_1)?;
    assert_eq!(buff_decrypted_1, buff_ciphertext_1);
    assert_ne!(buff_decrypted_1, PLAINTEXT);

    let tmp_decrypted_2 = tmp_path.join("decrypted_2");
    doby_cmd().unwrap().arg(tmp_decrypted_1).arg(&tmp_decrypted_2).assert().success().stdout("").stderr("");
    let buff_decrypted_2 = fs::read(tmp_decrypted_2)?;
    assert_eq!(buff_decrypted_2, PLAINTEXT);

    Ok(())
}

fn test_cipher(cipher_str: &str, cipher_algorithm: CipherAlgorithm) -> io::Result<()> {
    let (_, tmp_plaintext, tmp_ciphertext) = setup_files()?;

    doby_cmd().unwrap().arg("-c").arg(cipher_str).arg(tmp_plaintext).arg(&tmp_ciphertext).assert().success().stdout("").stderr("");

    let ciphertext = fs::read(&tmp_ciphertext)?;
    assert_eq!(ciphertext[4+SALT_LEN+4*3], cipher_algorithm as u8);
    assert_eq!(ciphertext.len(), PLAINTEXT.len()+17+SALT_LEN+HMAC_LEN);

    doby_cmd().unwrap().arg(tmp_ciphertext).assert().success().stdout(PLAINTEXT).stderr("");

    Ok(())
}

#[test]
fn xchacha20_cipher() -> io::Result<()> {
    test_cipher("xchacha20", CipherAlgorithm::XChaCha20)?;
    Ok(())
}

#[test]
fn aes_cipher() -> io::Result<()> {
    test_cipher("aes", CipherAlgorithm::AesCtr)?;
    Ok(())
}

#[test]
fn argon2_params() -> io::Result<()> {
    Command::cargo_bin("doby").unwrap().arg("-t").arg("0").assert().failure().stderr("Invalid Argon2 parameters: time cost is too small\n");
    Command::cargo_bin("doby").unwrap().arg("-m").arg("0").assert().failure().stderr("Invalid Argon2 parameters: memory cost is too small\n");
    Command::cargo_bin("doby").unwrap().arg("-p").arg("0").assert().failure().stderr("Invalid Argon2 parameters: not enough threads\n");

    let ciphertext = doby_cmd().unwrap().arg("-t").arg("8").arg("-m").arg("2048").arg("-p").arg("8").assert().success().stderr("").get_output().stdout.clone();
    assert_eq!(u32::from_be_bytes(ciphertext[4+SALT_LEN..4+SALT_LEN+4].try_into().unwrap()), 8); //time cost
    assert_eq!(u32::from_be_bytes(ciphertext[4+SALT_LEN+4..4+SALT_LEN+8].try_into().unwrap()), 2048); //memory cost
    assert_eq!(u32::from_be_bytes(ciphertext[4+SALT_LEN+8..4+SALT_LEN+12].try_into().unwrap()), 8); //parallelism

    Ok(())
}