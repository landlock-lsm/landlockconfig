use anyhow::{bail, Context};
use clap::Parser;
use landlockconfig::{build_ruleset, parse_json, parse_toml, restrict_self, RulesetStatus};
use std::fs::File;
use std::io::Read;
use std::os::unix::process::CommandExt;
use std::process::Command;

// TODO: Add option to only validate JSON and/or actual syscalls
//
// TODO: Warn about unused access rights, which might indicate that the
// configuration needs to be updated to leverage the latest Landlock access
// rights.  Add an option to disable this warning.
#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long, required_unless_present = "toml")]
    json: Option<String>,
    #[arg(short, long, required_unless_present = "json")]
    toml: Option<String>,
    #[arg(required = true)]
    command: Vec<String>,
}

enum ArgConfig {
    Json(String),
    Toml(String),
}

fn main() -> anyhow::Result<()> {
    let mut args = Args::parse();

    let arg_config = if let Some(json) = args.json.take() {
        ArgConfig::Json(json)
    } else {
        // Clap guarantees that toml is Some().
        ArgConfig::Toml(args.toml.take().unwrap())
    };

    let config = match arg_config {
        ArgConfig::Json(name) => {
            if name == "-" {
                parse_json(std::io::stdin())?
            } else {
                parse_json(File::open(name).context("Failed to open JSON file")?)?
            }
        }
        ArgConfig::Toml(name) => {
            let data = if name == "-" {
                let mut buffer = String::new();
                std::io::stdin().lock().read_to_string(&mut buffer)?;
                buffer
            } else {
                std::fs::read_to_string(name).context("Failed to open TOML file")?
            };
            parse_toml(data.as_str())?
        }
    };

    let ruleset = build_ruleset(&config)?;
    let status = restrict_self(ruleset, None)?;
    if status.ruleset == RulesetStatus::NotEnforced {
        bail!("Landlock is not supported by the running kernel.");
    }

    // clap guarantees that there is at least one element in command.
    let name = args.command.drain(0..1).next().unwrap();
    eprintln!("Executing {name} in a sandbox...");

    Err(Command::new(name).args(args.command).exec().into())
}
