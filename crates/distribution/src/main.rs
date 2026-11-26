#![allow(unexpected_cfgs)]
#[cfg(not(verus_keep_ghost))]
use verus_builtin_macros::verus;
#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

verus! {
/// Rust decodes one OS argument and supplies its original position, including argv[0].
pub fn argument<T, E>(index: usize, decoded: Result<T, E>) -> (out: Result<Option<T>, usize>)
    ensures out == match decoded {
        Err(_) => Err(index),
        Ok(value) => if index == 0 { Ok(None) } else { Ok(Some(value)) },
    },
{
    match decoded {
        Err(_) => Err(index),
        Ok(_) if index == 0 => Ok(None),
        Ok(value) => Ok(Some(value)),
    }
}

pub enum OutputStep<R, E> { Write(R, Result<(), E>), Flush(Result<(), E>) }

pub trait ReportOutput<R, E> {
    spec fn steps(&self) -> Seq<OutputStep<R, E>>;
    fn write(&mut self, report: R) -> (r: Result<(), E>)
        ensures self.steps() == old(self).steps().push(OutputStep::<R, E>::Write(report, r));
    fn flush(&mut self) -> (r: Result<(), E>)
        ensures self.steps() == old(self).steps().push(OutputStep::<R, E>::Flush(r));
}

/// A business failure skips stdout. A write failure skips flush. Each error keeps its origin.
pub fn publish<R, E, W: ReportOutput<R, E>>(command: Result<R, E>, output: &mut W)
    -> (result: Result<(), E>)
    ensures match command {
        Err(error) => output.steps() == old(output).steps() && result == Result::<(), E>::Err(error),
        Ok(report) => {
            let before = old(output).steps();
            ||| (result.is_err() && output.steps() == before.push(OutputStep::<R,E>::Write(report, result)))
            ||| output.steps() == before.push(OutputStep::<R,E>::Write(report, Ok(())))
                                        .push(OutputStep::<R,E>::Flush(result))
        },
    },
{
    let report = command?;
    output.write(report)?;
    output.flush()
}

pub enum Failure<E> { Argument(usize), Distribution(E) }

pub fn terminal<E>(result: Result<(), Failure<E>>) -> (out: (u8, Option<Failure<E>>))
    ensures out == match result {
        Ok(()) => (0u8, None),
        Err(Failure::Argument(index)) => (2u8, Some(Failure::Argument(index))),
        Err(Failure::Distribution(error)) => (1u8, Some(Failure::Distribution(error))),
    },
{
    match result {
        Ok(()) => (0, None),
        Err(error @ Failure::Argument(_)) => (2, Some(error)),
        Err(error @ Failure::Distribution(_)) => (1, Some(error)),
    }
}
}

#[cfg(not(verus_keep_ghost))]
mod native {
    use super::{Failure, ReportOutput, argument, publish};
    use serde_json::Value;
    use std::io::{self, Write};

    impl ReportOutput<Value, String> for io::StdoutLock<'_> {
        fn write(&mut self, report: Value) -> Result<(), String> {
            writeln!(self, "{report}").map_err(|e| e.to_string())
        }
        fn flush(&mut self) -> Result<(), String> {
            Write::flush(self).map_err(|e| e.to_string())
        }
    }

    pub(super) fn run() -> Result<(), Failure<String>> {
        let mut args = Vec::new();
        for (index, raw) in std::env::args_os().enumerate() {
            if let Some(text) = argument(index, raw.into_string()).map_err(Failure::Argument)? {
                args.push(text);
            }
        }
        publish(chrono_distribution::run(&args), &mut io::stdout().lock())
            .map_err(Failure::Distribution)
    }
}

#[cfg(not(verus_keep_ghost))]
fn main() -> std::process::ExitCode {
    let (code, failure) = terminal(native::run());
    match failure {
        Some(Failure::Argument(index)) => {
            eprintln!("E_USAGE: argument at argv index {index} must be valid UTF-8")
        }
        Some(Failure::Distribution(error)) => eprintln!("E_DISTRIBUTION: {error}"),
        None => {}
    }
    code.into()
}
