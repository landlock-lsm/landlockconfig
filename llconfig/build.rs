// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::process::Command;

fn run_git(args: &[&str]) -> String {
    // A one-off git invocation is simpler than pulling in a crate for this.
    Command::new("git")
        .args(args)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| {
            String::from_utf8_lossy(&output.stdout)
                .trim()
                .chars()
                .filter(|c| c.is_alphanumeric() || *c == '-')
                .collect()
        })
        .filter(|s: &String| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

fn main() {
    println!(
        "cargo:rustc-env=GIT_COMMIT={}",
        run_git(&[
            "describe",
            "--always",
            // Do not rely on local configuration (i.e. core.abbrev) for length.
            "--abbrev=12",
            "--exclude=*",
            "--dirty",
        ])
    );

    println!(
        "cargo:rustc-env=GIT_DATE={}",
        run_git(&["log", "--max-count=1", "--format=%cs"])
    );
}
