use clap::{Parser, Subcommand};
use predicate_receipt::{Decision, Policy, Receipt, evaluate, verify_receipt};
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Evaluate a JSON candidate and emit an admission receipt.
    Check {
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        input: PathBuf,
        /// Also write the receipt to this path.
        #[arg(long)]
        receipt: Option<PathBuf>,
        /// Emit compact JSON instead of pretty JSON.
        #[arg(long)]
        compact: bool,
    },
    /// Re-evaluate inputs and require an existing receipt to match exactly.
    Verify {
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        receipt: PathBuf,
    },
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(2),
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<bool, Box<dyn std::error::Error>> {
    match cli.command {
        Command::Check {
            policy,
            input,
            receipt,
            compact,
        } => {
            let (policy, policy_json) = read_policy(&policy)?;
            let candidate: Value = read_json(&input)?;
            let result = evaluate(&policy, &policy_json, &candidate)?;
            let output = if compact {
                serde_json::to_string(&result)?
            } else {
                serde_json::to_string_pretty(&result)?
            };
            println!("{output}");
            if let Some(path) = receipt {
                fs::write(path, format!("{output}\n"))?;
            }
            Ok(result.decision == Decision::Allow)
        }
        Command::Verify {
            policy,
            input,
            receipt,
        } => {
            let (policy, policy_json) = read_policy(&policy)?;
            let candidate: Value = read_json(&input)?;
            let receipt: Receipt = read_json(&receipt)?;
            verify_receipt(&policy, &policy_json, &candidate, &receipt)?;
            println!("receipt verified: {:?}", receipt.decision);
            Ok(true)
        }
    }
}

fn read_policy(path: &Path) -> Result<(Policy, Value), Box<dyn std::error::Error>> {
    let value: Value = read_json(path)?;
    let policy = serde_json::from_value(value.clone())?;
    Ok((policy, value))
}

fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T, Box<dyn std::error::Error>> {
    let content = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&content)?)
}
