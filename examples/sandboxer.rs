use anyhow::{bail, Context};
use clap::Parser;
use landlock::RulesetStatus;
use landlockconfig::Config;
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
    #[arg(short, long)]
    debug: bool,
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
                Config::parse_json(std::io::stdin())?
            } else {
                Config::parse_json(File::open(name).context("Failed to open JSON file")?)?
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
            Config::parse_toml(data.as_str())?
        }
    };

    if args.debug {
        eprintln!("{:#?}", config);
    }

    let (ruleset, rule_errors) = config.resolve()?.build_ruleset()?;
    if args.debug {
        eprintln!("Ignored rule errors: {:#?}", rule_errors);
    }

    let status = ruleset.restrict_self()?;
    if status.ruleset == RulesetStatus::NotEnforced {
        bail!("None of the restrictions can be enforced with the running kernel.");
    }

    // clap guarantees that there is at least one element in command.
    let name = args.command.drain(0..1).next().unwrap();
    eprintln!("Executing {name} in a sandbox...");

    Err(Command::new(name).args(args.command).exec().into())
}
