use std::{
    path::Path,
    fs::File,
    str::FromStr,
    io::{stdin, stdout, Read, Write},
};
use clap::{crate_name, crate_version, App, Arg};
use crate::crypto::ArgonParams;

pub struct CliArgs {
    pub password: String,
    pub force_encrypt: bool,
    pub argon2_params: ArgonParams,
    pub block_size: usize,
    pub reader: Box<dyn Read>,
    pub writer: Box<dyn Write>,
}

pub fn parse() -> Option<CliArgs> {
    let app = App::new(crate_name!())
        .version(crate_version!())
        .arg(Arg::with_name("INPUT").help("<PATH> | \"-\" or empty for stdin"))
        .arg(Arg::with_name("OUTPUT").help("<PATH> | \"-\" or empty for stdout"))
        .arg(
            Arg::with_name("force-encrypt")
                .short("f")
                .long("force-encrypt")
                .help(&format!("Encrypt even if {} format is recognized", crate_name!()))
        )
        .arg(
            Arg::with_name("password")
                .short("p")
                .long("password")
                .value_name("password")
        )
        .arg(
            Arg::with_name("t_cost")
                .short("i")
                .long("iterations")
                .value_name("iterations")
                .help("Argon2 time cost")
                .default_value("10")
        )
        .arg(
            Arg::with_name("m_cost")
                .short("m")
                .long("memory-cost")
                .value_name("memory cost")
                .help("Argon2 memory cost (in kilobytes)")
                .default_value("4096")
        )
        .arg(
            Arg::with_name("parallelism")
                .short("t")
                .long("threads")
                .value_name("threads")
                .help("Argon2 parallelism (between 1 and 255)")
                .default_value("4")
        )
        .arg(
            Arg::with_name("blocksize")
                .short("b")
                .long("block-size")
                .help("Size of file chunk (in bytes)")
                .default_value("65536")
        )
        .get_matches();

    let params = {
        let t_cost = number(app.value_of("t_cost").unwrap())?;
        let m_cost =  number(app.value_of("m_cost").unwrap())?;
        let parallelism =  number(app.value_of("parallelism").unwrap())?;

        ArgonParams {
            t_cost,
            m_cost,
            parallelism,
        }
    };

    let block_size = number(app.value_of("blocksize").unwrap())?;

    let input = app
        .value_of("INPUT")
        .and_then(|s| if s == "-" { None } else { Some(s) })
        .map(|s| Box::new(File::open(s).unwrap()) as Box<dyn Read>)
        .unwrap_or_else(|| Box::new(stdin()));

    let output = app
        .value_of("OUTPUT")
        .and_then(|s| if s == "-" { None } else { Some(s) })
        .map(|s| {
            if Path::new(s).exists() {
                eprintln!("{} already exists", s);
                None
            } else {
                Some(Box::new(File::create(s).unwrap()) as Box<dyn Write>)
            }
        })
        .unwrap_or_else(|| Some(Box::new(stdout())));

    let password = match app.value_of("password") {
        Some(s) => s.to_string(),
        None => rpassword::read_password_from_tty(Some("Password: ")).unwrap(),
    };

    Some(CliArgs {
        password,
        force_encrypt: app.is_present("force-encrypt"),
        argon2_params: params,
        block_size,
        reader: input,
        writer: output?,
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
