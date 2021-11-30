use std::{env, io};
use clap::Shell;
use doby::cli;

fn main() {
    let mut args = env::args().skip(1);
    if let Some(shell) = args.next() {
        if let Ok(shell) = shell.parse() {
            cli::app().gen_completions_to("doby", shell, &mut io::stdout());
        } else {
            eprintln!("error: invalid shell: {}", shell);
            eprintln!("shell variants: {:?}", Shell::variants());
        }
    } else {
        eprintln!("usage: compgen <shell>");
    }
}