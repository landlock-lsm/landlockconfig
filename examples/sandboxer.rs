// SPDX-License-Identifier: Apache-2.0 OR MIT

use anyhow::{bail, Context};
use clap::Parser;
use landlock::RulesetStatus;
use landlockconfig::{Config, ConfigFormat, OptionalConfig};
use std::fs::File;
use std::io::Read;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

// TODO: Add option to only validate JSON and/or actual syscalls
//
// TODO: Warn about unused access rights, which might indicate that the
// configuration needs to be updated to leverage the latest Landlock access
// rights.  Add an option to disable this warning.
#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long, required_unless_present = "toml")]
    json: Vec<String>,
    #[arg(short, long, required_unless_present = "json")]
    toml: Vec<String>,
    #[arg(short, long)]
    debug: bool,
    #[arg(required = true)]
    command: Vec<String>,
}

fn main() -> anyhow::Result<()> {
    let mut args = Args::parse();

    let stdin_count = args.json.iter().filter(|&path| path == "-").count()
        + args.toml.iter().filter(|&path| path == "-").count();
    if stdin_count > 1 {
        bail!("Stdin can only be used as configuration once");
    }

    let mut full_config = None;

    for json_path in args.json {
        let config = if json_path == "-" {
            Config::parse_json(std::io::stdin())?
        } else {
            let json_path = Path::new(&json_path);
            if json_path.is_dir() {
                Config::parse_directory(json_path, ConfigFormat::Json)?
            } else {
                Config::parse_json(File::open(json_path).context("Failed to open JSON file")?)?
            }
        };
        full_config.compose(&config);
    }

    for toml_path in args.toml {
        let config = if toml_path == "-" {
            let mut buffer = String::new();
            std::io::stdin().lock().read_to_string(&mut buffer)?;
            Config::parse_toml(buffer.as_str())?
        } else {
            let json_path = Path::new(&toml_path);
            if json_path.is_dir() {
                Config::parse_directory(&toml_path, ConfigFormat::Toml)?
            } else {
                let data =
                    std::fs::read_to_string(&toml_path).context("Failed to open TOML file")?;
                Config::parse_toml(data.as_str())?
            }
        };
        full_config.compose(&config);
    }

    let resolved = full_config
        .context("No configuration file provided")?
        .resolve()?;
    if args.debug {
        eprintln!("{:#?}", resolved);
    }

    let (ruleset, rule_errors) = resolved.build_ruleset()?;
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
