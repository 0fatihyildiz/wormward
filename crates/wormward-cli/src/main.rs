mod report;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use wormward_core::scan;
use wormward_packs::builtin_packs;

#[derive(Parser)]
#[command(name = "wormward", version, about = "Detect and remove supply-chain worms")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Scan directories for infections (read-only).
    Scan {
        /// Directories to scan (default: current directory).
        #[arg(default_value = ".")]
        dirs: Vec<PathBuf>,
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    /// List the campaign packs compiled into this build.
    ListPacks,
}

#[derive(Copy, Clone, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Scan { dirs, format } => {
            for dir in &dirs {
                if !dir.exists() {
                    eprintln!("error: path does not exist: {}", dir.display());
                    return ExitCode::from(2);
                }
            }
            let report = scan(&dirs, &builtin_packs());
            match format {
                OutputFormat::Text => print!("{}", report::render_text(&report)),
                OutputFormat::Json => println!("{}", report::render_json(&report)),
            }
            if report.findings.is_empty() {
                ExitCode::from(0)
            } else {
                ExitCode::from(1)
            }
        }
        Command::ListPacks => {
            for pack in builtin_packs() {
                println!("{} — {}", pack.manifest.id, pack.manifest.name);
            }
            ExitCode::from(0)
        }
    }
}
