// SPDX-License-Identifier: Apache-2.0 OR MIT

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "landlock-policy",
    about = "Develop, inspect, and transform Landlock policies",
    long_about = "landlock-policy develops, inspects, and transforms Landlock policies \
        expressed as JSON or TOML.",
    version = concat!(env!("CARGO_PKG_VERSION"), " (", env!("GIT_COMMIT"), " ", env!("GIT_DATE"), ")")
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    #[command(
        about = "Print the JSON schema for Landlock policies",
        long_about = "Output the canonical JSON schema that describes the structure and \
            validation rules for Landlock policy files. The schema is printed to stdout in \
            JSON format."
    )]
    Schema,
}

fn schema() {
    print!(
        "{}",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../schema/landlock-policy.json"
        ))
    );
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Schema => schema(),
    }
}
