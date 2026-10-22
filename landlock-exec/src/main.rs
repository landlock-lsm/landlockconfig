// SPDX-License-Identifier: Apache-2.0 OR MIT

use anyhow::{bail, Context};
use clap::Parser;
use landlock::RulesetStatus;
use landlock_policy::{OptionalPolicy, Policy, PolicyFormat};
use std::fs::File;
use std::io::Read;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

#[derive(Parser)]
#[command(
    name = "landlock-exec",
    about = "Apply Landlock policies and execute a command",
    long_about = "Apply Landlock restrictions from JSON or TOML policy files, then replace \
        landlock-exec with the requested command. Multiple policy files can be provided \
        and will be composed together."
)]
struct Cli {
    #[arg(
        short,
        long,
        required_unless_present = "toml",
        help = "JSON policy file(s) to load",
        long_help = "Path to a JSON policy file, or '-' to read from stdin. \
            Can be specified multiple times; policies are composed in order. \
            Directories are also supported."
    )]
    json: Vec<String>,

    #[arg(
        short,
        long,
        required_unless_present = "json",
        help = "TOML policy file(s) to load",
        long_help = "Path to a TOML policy file, or '-' to read from stdin. \
            Can be specified multiple times; policies are composed in order. \
            Directories are also supported."
    )]
    toml: Vec<String>,

    #[arg(short, long, help = "Print resolved policy and ignored errors")]
    debug: bool,

    #[arg(
        trailing_var_arg = true,
        required = true,
        num_args = 1..,
        help = "Command to execute in the sandbox"
    )]
    command: Vec<String>,
}

fn run(
    json: Vec<String>,
    toml: Vec<String>,
    debug: bool,
    mut command: Vec<String>,
) -> anyhow::Result<()> {
    let stdin_count = json.iter().filter(|&path| path == "-").count()
        + toml.iter().filter(|&path| path == "-").count();
    if stdin_count > 1 {
        bail!("Standard input can only be used for one policy");
    }

    let mut full_policy = None;

    for json_path in json {
        let policy = if json_path == "-" {
            Policy::parse_json(std::io::stdin())?
        } else {
            let json_path = Path::new(&json_path);
            if json_path.is_dir() {
                Policy::parse_directory(json_path, PolicyFormat::Json)?
            } else {
                Policy::parse_json(File::open(json_path).context("Failed to open JSON file")?)?
            }
        };
        full_policy.compose(&policy);
    }

    for toml_path in toml {
        let policy = if toml_path == "-" {
            let mut buffer = String::new();
            std::io::stdin().lock().read_to_string(&mut buffer)?;
            Policy::parse_toml(buffer.as_str())?
        } else {
            let toml_path = Path::new(&toml_path);
            if toml_path.is_dir() {
                Policy::parse_directory(toml_path, PolicyFormat::Toml)?
            } else {
                let data =
                    std::fs::read_to_string(toml_path).context("Failed to open TOML file")?;
                Policy::parse_toml(data.as_str())?
            }
        };
        full_policy.compose(&policy);
    }

    let resolved = full_policy.context("No policy file provided")?.resolve()?;
    if debug {
        eprintln!("{:#?}", resolved);
    }

    let (ruleset, rule_errors) = resolved.build_ruleset()?;
    if debug {
        eprintln!("Ignored rule errors: {:#?}", rule_errors);
    }

    let status = ruleset.restrict_self()?;
    if status.ruleset == RulesetStatus::NotEnforced {
        bail!("None of the restrictions can be enforced with the running kernel.");
    }

    // clap guarantees that there is at least one element in command.
    let name = command.drain(0..1).next().unwrap();
    eprintln!("Executing {name} in a sandbox...");

    Err(Command::new(name).args(command).exec().into())
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    run(cli.json, cli.toml, cli.debug, cli.command)
}
