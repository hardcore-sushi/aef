use std::{io::{self, Read, Write}, fs::{File, create_dir}, path::PathBuf};
use assert_cmd::{Command, cargo::{CargoError, cargo_bin}};
use tempfile::TempDir;

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
    cmd.arg("-p").arg(PASSWORD);
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

    let tmp_decrypted = tmp_path.join("decryped");
    doby_cmd().unwrap().arg(tmp_ciphertext).arg(&tmp_decrypted).assert().success().stdout("").stderr("");

    let mut buff = [0; PLAINTEXT.len()];
    assert_eq!(File::open(tmp_decrypted)?.read(&mut buff)?, PLAINTEXT.len());
    assert_eq!(buff, PLAINTEXT);

    Ok(())
}

#[test]
fn stdout() -> io::Result<()> {
    let (_, tmp_plaintext, tmp_ciphertext) = setup_files()?;
    
    let shell_cmd = format!("{} -p \"{}\" {} > {}", cargo_bin("doby").to_str().unwrap(), PASSWORD, tmp_plaintext.to_str().unwrap(), tmp_ciphertext.to_str().unwrap());
    bash_cmd().arg(shell_cmd).assert().success().stdout("").stderr("");
    
    doby_cmd().unwrap().arg(tmp_ciphertext).assert().success().stdout(PLAINTEXT);

    Ok(())
}

#[test]
fn stdin() -> io::Result<()> {
    let (_, tmp_plaintext, tmp_ciphertext) = setup_files()?;

    let mut shell_cmd = format!("cat {} | {} -p \"{}\" - {}", tmp_plaintext.to_str().unwrap(), cargo_bin("doby").to_str().unwrap(), PASSWORD, tmp_ciphertext.to_str().unwrap());
    bash_cmd().arg(shell_cmd).assert().success().stdout("").stderr("");

    shell_cmd = format!("cat {} | {} -p \"{}\"", tmp_ciphertext.to_str().unwrap(), cargo_bin("doby").to_str().unwrap(), PASSWORD);
    bash_cmd().arg(shell_cmd).assert().success().stdout(PLAINTEXT);

    Ok(())
}

#[test]
fn argon2_params() -> io::Result<()> {
    Command::cargo_bin("doby").unwrap().arg("-i").arg("0").assert().failure().stderr("Invalid argon2 params: time cost is too small\n");
    Command::cargo_bin("doby").unwrap().arg("-m").arg("0").assert().failure().stderr("Invalid argon2 params: memory cost is too small\n");
    Command::cargo_bin("doby").unwrap().arg("-t").arg("0").assert().failure().stderr("Invalid argon2 params: too few lanes\n");
    Ok(())
}