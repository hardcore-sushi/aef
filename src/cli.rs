use std::{
    path::Path,
    fs::File,
    str::FromStr,
    io::{stdin, stdout, Read},
};
use clap::{crate_name, crate_version, App, Arg, AppSettings};
use crate::{LazyWriter, WrappedPassword, crypto::CipherAlgorithm};

cpufeatures::new!(aes_ni, "aes");

pub struct CliArgs {
    pub password: WrappedPassword,
    pub force_encrypt: bool,
    pub argon2_params: argon2::Params,
    pub cipher: CipherAlgorithm,
    pub block_size: usize,
    pub reader: Box<dyn Read>,
    pub writer: LazyWriter<String>,
}

pub fn parse() -> Option<CliArgs> {
    let app = App::new(crate_name!())
        .version(crate_version!())
        .setting(AppSettings::ColoredHelp)
        .about("Secure symmetric encryption from the command line.")
        .arg(Arg::with_name("INPUT").help("<PATH> | \"-\" or empty for stdin"))
        .arg(Arg::with_name("OUTPUT").help("<PATH> | \"-\" or empty for stdout"))
        .arg(
            Arg::with_name("force-encrypt")
                .short("f")
                .long("force-encrypt")
                .help(&format!("Encrypt even if {} format is recognized", crate_name!()))
        )
        .arg(
            Arg::with_name("1_password")
                .long("password")
                .value_name("password")
                .help("Password used to derive encryption keys")
        )
        .arg(
            Arg::with_name("2_t_cost")
                .short("t")
                .long("time-cost")
                .value_name("number of iterations")
                .help("Argon2 time cost")
                .default_value("10")
        )
        .arg(
            Arg::with_name("3_m_cost")
                .short("m")
                .long("memory-cost")
                .value_name("memory cost")
                .help("Argon2 memory cost (in kilobytes)")
                .default_value("4096")
        )
        .arg(
            Arg::with_name("4_p_cost")
                .short("p")
                .long("parallelism")
                .value_name("degree of parallelism")
                .help("Argon2 parallelism cost")
                .default_value("4")
        )
        .arg(
            Arg::with_name("blocksize")
                .short("b")
                .long("block-size")
                .help("Size of the I/O buffer (in bytes)")
                .default_value("65536")
        )
        .arg(
            Arg::with_name("cipher")
                .short("c")
                .long("cipher")
                .value_name("cipher")
                .help("Encryption cipher to use")
                .long_help("Encryption cipher to use. By default, AES is selected if AES-NI is supported. Otherwise, XChaCha20 is used.")
                .possible_values(&["aes", "xchacha20"])
                .case_insensitive(true)
        )
        .get_matches();

    let params = {
        let t_cost = number(app.value_of("2_t_cost").unwrap())?;
        let m_cost =  number(app.value_of("3_m_cost").unwrap())?;
        let p_cost =  number(app.value_of("4_p_cost").unwrap())?;

        match argon2::Params::new(m_cost, t_cost, p_cost, None) {
            Ok(params) => Some(params),
            Err(e) => {
                eprintln!("Invalid Argon2 parameters: {}", e);
                None
            }
        }
    }?;

    let cipher = app
        .value_of("cipher")
        .map(|s| if s.to_lowercase() == "aes" {
                CipherAlgorithm::AesCtr
            } else {
                CipherAlgorithm::XChaCha20
            }
        )
        .unwrap_or_else(|| if aes_ni::get() {
                CipherAlgorithm::AesCtr
            } else {
                CipherAlgorithm::XChaCha20
            }
        );

    let block_size = number(app.value_of("blocksize").unwrap())?;

    let input = match app
        .value_of("INPUT")
        .and_then(|s| if s == "-" { None } else { Some(s) })
        {
            Some(s) => 
                Box::new(
                    File::open(s)
                        .map_err(|e| eprintln!("{}: {}", s, e))
                        .ok()?
                ) as Box<dyn Read>
            ,
            None => Box::new(stdin())
        };

    let output = app
        .value_of("OUTPUT")
        .and_then(|s| if s == "-" { None } else { Some(s) })
        .map(|s| {
            if Path::new(s).exists() {
                eprintln!("WARNING: {} already exists", s);
                None
            } else {
                Some(LazyWriter::from_path(s.to_owned()))
            }
        })
        .unwrap_or_else(|| Some(LazyWriter::from_writer(stdout())))?;

    Some(CliArgs {
        password: app.value_of("1_password").into(),
        force_encrypt: app.is_present("force-encrypt"),
        argon2_params: params,
        cipher,
        block_size,
        reader: input,
        writer: output,
    })
}

fn number<T: FromStr>(val: &str) -> Option<T> {
    match val.parse::<T>() {
        Ok(n) => Some(n),
        Err(_) => {
            eprintln!("Cannot parse '{}' to '{}'", val, std::any::type_name::<T>());
            None
        }
    }
}
