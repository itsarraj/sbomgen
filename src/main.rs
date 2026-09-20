use std::fs;
use std::path::PathBuf;

use chrono::Utc;
use clap::Parser;
use sbomgen::cyclonedx::build_bom;
use sbomgen::lockfile::detect_and_parse;
use uuid::Uuid;

#[derive(Parser)]
#[command(
    name = "sbomgen",
    about = "Generates a CycloneDX 1.5 JSON SBOM from a Cargo.lock, package-lock.json, or requirements.txt"
)]
struct Cli {
    /// Lockfile to generate an SBOM from.
    lockfile: PathBuf,
    /// Write the SBOM JSON here instead of stdout.
    #[arg(short, long)]
    output: Option<PathBuf>,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let content = fs::read_to_string(&cli.lockfile)
        .map_err(|e| anyhow::anyhow!("reading {}: {e}", cli.lockfile.display()))?;
    let filename = cli
        .lockfile
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or("");

    let components = detect_and_parse(filename, &content).map_err(|e| anyhow::anyhow!("{e}"))?;
    let bom = build_bom(
        &components,
        Utc::now().to_rfc3339(),
        format!("urn:uuid:{}", Uuid::new_v4()),
    );
    let json = serde_json::to_string_pretty(&bom)?;

    match cli.output {
        Some(path) => {
            fs::write(&path, &json)
                .map_err(|e| anyhow::anyhow!("writing {}: {e}", path.display()))?;
            eprintln!(
                "wrote {} component(s) to {}",
                bom.components.len(),
                path.display()
            );
        }
        None => println!("{json}"),
    }

    Ok(())
}
