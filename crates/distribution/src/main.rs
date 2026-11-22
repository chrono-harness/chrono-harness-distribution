use std::{
    env,
    io::{self, Write},
    process::ExitCode,
};

fn main() -> ExitCode {
    let mut args = Vec::new();
    for (index, argument) in env::args_os().enumerate() {
        let Ok(text) = argument.into_string() else {
            eprintln!("E_USAGE: argument at argv index {index} must be valid UTF-8");
            return 2.into();
        };
        if index != 0 {
            args.push(text);
        }
    }
    match chrono_distribution::run(&args) {
        Ok(report) => {
            let mut output = io::stdout().lock();
            if let Err(error) = writeln!(output, "{report}").and_then(|()| output.flush()) {
                eprintln!("E_DISTRIBUTION: {error}");
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("E_DISTRIBUTION: {error}");
            ExitCode::FAILURE
        }
    }
}
