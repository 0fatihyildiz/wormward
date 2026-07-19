mod online;
mod report;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use wormward_core::{scan, scan_deep};
use wormward_osm::OsmClient;
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
        /// Cross-check npm-package and domain findings against the live OSM API.
        #[arg(long)]
        online: bool,
        /// OSM API token (else OSM_API_KEY env).
        #[arg(long)]
        osm_token: Option<String>,
        /// Also scan the tip of every local/remote branch (read-only, no checkout).
        #[arg(long)]
        deep: bool,
    },
    /// List the campaign packs compiled into this build.
    ListPacks,
    /// Check a single asset against the live OSM database.
    Check {
        /// report_type: package | repository | url | domain | ip | wallet | container
        #[arg(long = "type")]
        report_type: String,
        #[arg(long)]
        ecosystem: Option<String>,
        #[arg(long)]
        version: Option<String>,
        /// OSM API token (else OSM_API_KEY env).
        #[arg(long)]
        osm_token: Option<String>,
        identifier: String,
    },
}

#[derive(Copy, Clone, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

fn osm_base_url() -> String {
    std::env::var("OSM_BASE_URL")
        .unwrap_or_else(|_| "https://api.opensourcemalware.com/functions/v1".to_string())
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Scan { dirs, format, online, osm_token, deep } => {
            for dir in &dirs {
                if !dir.exists() {
                    eprintln!("error: path does not exist: {}", dir.display());
                    return ExitCode::from(2);
                }
            }
            let mut report = if deep {
                scan_deep(&dirs, &builtin_packs())
            } else {
                scan(&dirs, &builtin_packs())
            };
            if online {
                let token = osm_token
                    .or_else(|| std::env::var("OSM_API_KEY").ok())
                    .filter(|t| !t.is_empty());
                let token = match token {
                    Some(t) => t,
                    None => {
                        eprintln!("error: --online requires an OSM token (--osm-token or OSM_API_KEY)");
                        return ExitCode::from(2);
                    }
                };
                let client = OsmClient::new(osm_base_url(), token);
                for w in online::enrich(&mut report.findings, &client) {
                    eprintln!("warning: {w}");
                }
            }
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
        Command::Check { report_type, ecosystem, version, osm_token, identifier } => {
            let token = osm_token
                .or_else(|| std::env::var("OSM_API_KEY").ok())
                .filter(|t| !t.is_empty());
            let token = match token {
                Some(t) => t,
                None => {
                    eprintln!("error: check requires an OSM token (--osm-token or OSM_API_KEY)");
                    return ExitCode::from(2);
                }
            };
            let client = OsmClient::new(osm_base_url(), token);
            match client.check(&wormward_osm::CheckQuery {
                report_type,
                resource_identifier: identifier,
                ecosystem,
                version,
            }) {
                Ok(r) => {
                    println!("malicious: {}", r.malicious);
                    if !r.osm_url.is_empty() {
                        println!("osm_url: {}", r.osm_url);
                    }
                    if let Some(d) = r.details {
                        println!("threat: {} ({})", d.description, d.severity_level);
                    }
                    if r.malicious {
                        ExitCode::from(1)
                    } else {
                        ExitCode::from(0)
                    }
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::from(2)
                }
            }
        }
    }
}
