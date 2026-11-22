use std::{env, fs, process::ExitCode};

fn main() -> ExitCode {
    let args: Vec<_> = env::args().skip(1).collect();
    let args: Vec<_> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["status", "--porcelain"] => match fs::read("source") {
            Ok(bytes) if bytes == b"real input" => (),
            Ok(_) => println!(" M source"),
            Err(_) => return ExitCode::FAILURE,
        },
        ["rev-parse", "HEAD"] => println!("{}", "a".repeat(40)),
        ["rev-parse", "HEAD^{tree}"] => println!("{}", "b".repeat(40)),
        _ => return ExitCode::FAILURE,
    }
    ExitCode::SUCCESS
}
