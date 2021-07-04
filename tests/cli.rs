use std::{io::{self, Read, Write}, fs::File, path::PathBuf};
use assert_cmd::{Command, cargo::CargoError};
use tempfile::{NamedTempFile, TempDir};

fn doby_cmd<>() -> Result<Command, CargoError> {
    const PASSWORD: &str = "the password";
    let mut cmd = Command::cargo_bin("doby")?;
    cmd.arg("-p").arg(PASSWORD);
    Ok(cmd)
}

#[test]
fn files() -> io::Result<()> {
    const PLAINTEXT: &[u8] = b"the plaintext";

    let tmp_dir = TempDir::new()?;
    let tmp_path = PathBuf::from(tmp_dir.path());

    let mut tmp_plaintext = NamedTempFile::new_in(&tmp_dir)?;
    tmp_plaintext.write_all(PLAINTEXT)?;
    let tmp_ciphertext = tmp_path.join("ciphertext");
    doby_cmd().unwrap().arg(tmp_plaintext.path()).arg(&tmp_ciphertext).assert().success().stdout("").stderr("");

    let tmp_decrypted = tmp_path.join("decryped");
    doby_cmd().unwrap().arg(tmp_ciphertext).arg(&tmp_decrypted).assert().success().stdout("").stderr("");

    let mut tmp_decrypted = File::open(tmp_decrypted).unwrap();
    let mut buff = [0; PLAINTEXT.len()];
    assert_eq!(tmp_decrypted.read(&mut buff)?, PLAINTEXT.len());
    assert_eq!(buff, PLAINTEXT);

    Ok(())
}

#[test]
fn argon2_params() -> io::Result<()> {
    Command::cargo_bin("doby").unwrap().arg("-i").arg("0").assert().failure().stderr("Invalid argon2 params: time cost is too small\n");
    Command::cargo_bin("doby").unwrap().arg("-m").arg("0").assert().failure().stderr("Invalid argon2 params: memory cost is too small\n");
    Command::cargo_bin("doby").unwrap().arg("-t").arg("0").assert().failure().stderr("Invalid argon2 params: too few lanes\n");
    Ok(())
}