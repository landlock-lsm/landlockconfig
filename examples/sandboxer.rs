use anyhow::{bail, Context};
use clap::Parser;
use landlockconfig::{build_ruleset, parse_config, restrict_self, RulesetStatus};
use std::fs::File;
use std::os::unix::process::CommandExt;
use std::process::Command;

// TODO: Add option to only validate JSON and/or actual syscalls
//
// TODO: Warn about unused access rights, which might indicate that the
// configuration needs to be updated to leverage the latest Landlock access
// rights.  Add an option to disable this warning.
#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long)]
    config: String,
    #[arg(required = true)]
    command: Vec<String>,
}

fn main() -> anyhow::Result<()> {
    let mut args = Args::parse();

    let config = if args.config == "-" {
        parse_config(std::io::stdin())?
    } else {
        parse_config(File::open(args.config).context("Failed to open configuration file")?)?
    };

    let ruleset = build_ruleset(&config, None)?;
    let status = restrict_self(ruleset, None)?;
    if status.ruleset == RulesetStatus::NotEnforced {
        bail!("Landlock is not supported by the running kernel.");
    }

    // clap guarantees that there is at least one element in command.
    let name = args.command.drain(0..1).next().unwrap();
    eprintln!("Executing {name} in a sandbox...");

    Err(Command::new(name).args(args.command).exec().into())
}
