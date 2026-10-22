// SPDX-License-Identifier: Apache-2.0 OR MIT

use anyhow::{bail, Context};
use clap::{Parser, Subcommand};
use landlock::RulesetStatus;
use landlockconfig::{Config, ConfigFormat, OptionalConfig};
use std::fs::File;
use std::io::Read;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

#[derive(Parser)]
#[command(
    name = "llconfig",
    about = "Command-line tool for the Landlock Config format",
    long_about = "llconfig is a simple command-line tool for the Landlock Config format. \
        It reads Landlock configurations expressed as JSON or TOML and applies operations on them.",
    version = concat!(env!("CARGO_PKG_VERSION"), " (", env!("GIT_COMMIT"), " ", env!("GIT_DATE"), ")")
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    #[command(
        about = "Execute a command in a sandboxed environment",
        long_about = "Run a command with Landlock security restrictions applied based on the \
            specified JSON or TOML configuration files. Multiple configurations can be provided \
            and will be composed together."
    )]
    Run {
        #[arg(
            short,
            long,
            required_unless_present = "toml",
            help = "JSON configuration file(s) to load",
            long_help = "Path to a JSON configuration file, or '-' to read from stdin. \
                Can be specified multiple times; configurations are composed in order. \
                Directories are also supported."
        )]
        json: Vec<String>,

        #[arg(
            short,
            long,
            required_unless_present = "json",
            help = "TOML configuration file(s) to load",
            long_help = "Path to a TOML configuration file, or '-' to read from stdin. \
                Can be specified multiple times; configurations are composed in order. \
                Directories are also supported."
        )]
        toml: Vec<String>,

        #[arg(short, long, help = "Print resolved configuration and ignored errors")]
        debug: bool,

        #[arg(
            trailing_var_arg = true,
            required = true,
            num_args = 1..,
            help = "Command to execute in the sandbox"
        )]
        command: Vec<String>,
    },

    #[command(
        about = "Print the JSON schema for Landlock configurations",
        long_about = "Output the versioned JSON schema that describes the structure and \
            validation rules for Landlock configuration files. The schema is printed to \
            stdout in JSON format."
    )]
    Schema,
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
        bail!("Stdin can only be used as configuration once");
    }

    let mut full_config = None;

    for json_path in json {
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

    for toml_path in toml {
        let config = if toml_path == "-" {
            let mut buffer = String::new();
            std::io::stdin().lock().read_to_string(&mut buffer)?;
            Config::parse_toml(buffer.as_str())?
        } else {
            let toml_path = Path::new(&toml_path);
            if toml_path.is_dir() {
                Config::parse_directory(toml_path, ConfigFormat::Toml)?
            } else {
                let data =
                    std::fs::read_to_string(toml_path).context("Failed to open TOML file")?;
                Config::parse_toml(data.as_str())?
            }
        };
        full_config.compose(&config);
    }

    let resolved = full_config
        .context("No configuration file provided")?
        .resolve()?;
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

fn schema() {
    print!(
        "{}",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../schema/landlockconfig.json"
        ))
    );
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Run {
            json,
            toml,
            debug,
            command,
        } => run(json, toml, debug, command),
        Commands::Schema => {
            schema();
            Ok(())
        }
    }
}
