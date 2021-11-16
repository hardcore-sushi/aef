use std::{fs::File, io::{self, Read, stdin, stdout}, path::Path, str::FromStr};
use clap::{crate_name, crate_version, App, Arg, AppSettings};
use crate::{WrappedWriter, WrappedPassword, crypto::CipherAlgorithm};

cpufeatures::new!(aes_ni, "aes");

pub struct CliArgs {
    pub password: WrappedPassword,
    pub force_encrypt: bool,
    pub argon2_params: argon2::Params,
    pub cipher: CipherAlgorithm,
    pub block_size: usize,
    pub reader: Box<dyn Read>,
    pub writer: WrappedWriter<String>,
}

pub struct ParseResult {
    pub error: bool,
    pub cli_args: Option<CliArgs>,
}

impl ParseResult {
    fn exited() -> Self {
        Self { error: false, cli_args: None }
    }
}

impl From<CliArgs> for ParseResult {
    fn from(args: CliArgs) -> Self {
        ParseResult { error: false, cli_args: Some(args) }
    }
}

pub fn parse() -> Option<ParseResult> {
    let app = App::new(crate_name!())
        .version(crate_version!())
        .setting(AppSettings::ColoredHelp)
        .about("Secure symmetric encryption from the command line.")
        .arg(Arg::with_name("INPUT").help("<PATH> | \"-\" or empty for stdin"))
        .arg(Arg::with_name("OUTPUT").help("<PATH> | \"-\" or empty for stdout"))
        .arg(
            Arg::with_name("1_force_encrypt")
                .short("f")
                .long("force-encrypt")
                .help(&format!("Encrypt even if {} format is recognized", crate_name!()))
        )
        .arg(
            Arg::with_name("2_interactive")
                .short("i")
                .long("interactive")
                .help("Prompt before overwriting files")
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
                .value_name("iterations")
                .help("Argon2 time cost")
                .default_value("10")
        )
        .arg(
            Arg::with_name("3_m_cost")
                .short("m")
                .long("memory-cost")
                .value_name("memory size")
                .help("Argon2 memory cost (in kilobytes)")
                .default_value("4096")
        )
        .arg(
            Arg::with_name("4_p_cost")
                .short("p")
                .long("parallelism")
                .value_name("threads")
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

    let wrapped_writer = match app
        .value_of("OUTPUT")
        .and_then(|s| if s == "-" { None } else { Some(s) }) {
            Some(path) => {
                if {
                    if app.is_present("2_interactive") && Path::new(path).exists() {
                        eprint!("Warning: {} already exists. Overwrite [y/N]? ", path);
                        let mut c = String::with_capacity(2);
                        io::stdin().read_line(&mut c).unwrap();
                        !c.is_empty() && c.chars().nth(0).unwrap() == 'y'
                    } else {
                        true
                    }
                } {
                    WrappedWriter::from_path(path.to_string())
                } else {
                    return Some(ParseResult::exited())
                }
            }
            None => WrappedWriter::from_writer(stdout())
        };

    Some(CliArgs {
        password: app.value_of("1_password").into(),
        force_encrypt: app.is_present("1_force_encrypt"),
        argon2_params: params,
        cipher,
        block_size,
        reader: input,
        writer: wrapped_writer,
    }.into())
}

fn number<T: FromStr>(val: &str) -> Option<T> {
    match val.parse::<T>() {
        Ok(n) => Some(n),
        Err(_) => {
            eprintln!("Error: '{}' is not a number", val);
            None
        }
    }
}
