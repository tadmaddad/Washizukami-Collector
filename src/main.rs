mod collector;
mod config;
mod exttools;
mod logger;
mod ntfs_reader;
mod path_resolver;
mod privileges;
mod scan;
mod ui;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use collector::{collect_artifact, CollectionStatus, RawCollector};
use config::CollectionFilter;
use std::io::Write;
use std::path::{Path, PathBuf};

// ── CLI definition ────────────────────────────────────────────────────────────

/// Washizukami (鷲掴) — fast forensic artifact collector.
///
/// Collects Windows artifacts (event logs, registry hives, filesystem items)
/// using raw NTFS access to bypass OS file locks.
/// Must be run as Administrator.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Output directory.
    /// Defaults to <exe_dir>/output/<COMPUTERNAME>.
    #[arg(short, long, value_name = "DIR")]
    output: Option<PathBuf>,

    /// Collect only these artifact names (case-insensitive, repeatable).
    /// Example: --artifact "SAM Registry Hive" --artifact "Security Event Log"
    #[arg(short, long = "artifact", value_name = "NAME")]
    artifacts: Vec<String>,

    /// Exclude all artifacts in this category (case-insensitive, repeatable).
    /// Example: --exclude-category EventLogs --exclude-category Registry
    #[arg(short = 'x', long = "exclude-category", value_name = "CATEGORY")]
    exclude_categories: Vec<String>,

    /// List matching artifacts and their resolved paths, then exit without
    /// collecting anything.
    #[arg(long)]
    dry_run: bool,

    /// After collection, compress the output directory into a ZIP archive
    /// alongside it: <output_dir>.zip
    #[arg(long)]
    zip: bool,

    /// Override the source drive letter used for NTFS raw access.
    /// Defaults to the drive letter in each artifact's target_path.
    /// Example: --volume D
    #[arg(long, value_name = "LETTER")]
    volume: Option<char>,

    /// Capture a full memory dump using tools/winpmem.exe (must be present).
    /// The dump is written to <output_dir>/memory.dmp.
    #[arg(long)]
    mem: bool,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Scan collected artifacts with a YARA engine.
    Scan {
        /// Path to the YARA engine executable.
        #[arg(long, value_name = "PATH", default_value = "./tools/yr.exe")]
        yara_path: PathBuf,

        /// Path to the YARA rules file to use for scanning.
        #[arg(long, value_name = "FILE")]
        rules: PathBuf,

        /// Directory where scan results will be written.
        #[arg(long, value_name = "DIR")]
        output: PathBuf,
    },
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    ui::init();

    let cli = Cli::parse();

    // ── Subcommand dispatch ───────────────────────────────────────────────────
    if let Some(Commands::Scan { yara_path, rules, output }) = cli.command {
        scan::run_scan(scan::ScanArgs { yara_path, rules, output });
        return Ok(());
    }

    // ── Pre-flight checks ────────────────────────────────────────────────────
    privileges::require_elevation()?;

    // Hostname → top-level output subdirectory.
    let hostname = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".to_owned());

    // Resolve paths relative to the executable so the tool works correctly
    // regardless of the current working directory.
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_owned()))
        .unwrap_or_else(|| PathBuf::from("."));

    let output_base = cli
        .output
        .unwrap_or_else(|| exe_dir.join("output").join(&hostname));

    // ── Build CLI filter ─────────────────────────────────────────────────────
    let cli_filter = CollectionFilter {
        enabled_artifacts: cli.artifacts,
        disabled_categories: cli.exclude_categories,
    };
    let cli_filter_opt = if cli_filter.is_empty() {
        None
    } else {
        Some(&cli_filter)
    };

    // ── Load artifact definitions ────────────────────────────────────────────
    let definitions = config::load_artifacts(&exe_dir, cli_filter_opt)?;

    // ── Header ───────────────────────────────────────────────────────────────
    ui::print_header(
        &hostname,
        cli.volume,
        cli.dry_run,
        definitions.len(),
        &output_base,
        &output_base.join("collection.log"),
    );

    // ── Dry-run path: resolve and print, then exit ───────────────────────────
    if cli.dry_run {
        run_dry(&definitions);
        return Ok(());
    }

    // ── Confirmation prompt ──────────────────────────────────────────────────
    if !ui::confirm("Start collection? [y/N]:") {
        ui::print_info("Aborted.");
        return Ok(());
    }
    println!();

    // ── Open audit log ───────────────────────────────────────────────────────
    let mut audit = logger::AuditLogger::new(&output_base)?;

    // ── Memory dump (winpmem) — runs before artifact collection ───────────────
    if cli.mem {
        exttools::run_winpmem(&exe_dir, &output_base, &mut audit)
            .context("memory dump failed")?;
    }

    // ── Collection loop ──────────────────────────────────────────────────────
    // RawCollector is shared across all artifacts so that volume handles
    // (\\.\\C: etc.) are only opened and parsed once per run.
    let mut raw_collector = RawCollector::new();

    let mut n_ok: usize = 0;
    let mut n_skip: usize = 0;
    let mut n_fail: usize = 0;

    for def in &definitions {
        // Expand environment variables and glob wildcards.
        let resolved = match path_resolver::resolve_path(&def.target_path) {
            Ok(paths) => paths,
            Err(e) => {
                ui::print_warn(&format!(
                    "path resolution failed for '{}': {:#}",
                    def.name, e
                ));
                audit.log_warn(&format!("path resolution failed for '{}': {:#}", def.name, e));
                n_fail += 1;
                continue;
            }
        };

        if resolved.is_empty() {
            ui::print_skip(
                &def.category,
                &def.name,
                &format!("no files matched '{}'", def.target_path),
            );
            audit.log_warn(&format!("no paths matched: {}", def.target_path));
            n_skip += 1;
            continue;
        }

        for source_path in &resolved {
            let result = collect_artifact(def, source_path, &output_base, &mut raw_collector);

            match &result.status {
                CollectionStatus::Success => {
                    let method_tag = match (result.method_used.clone(), result.fell_back) {
                        (_, true) => "NTFS-fallback",
                        (config::CollectionMethod::NTFS, _) => "NTFS",
                        (config::CollectionMethod::File, _) => "File",
                    };
                    ui::print_ok(
                        &def.category,
                        &def.name,
                        method_tag,
                        result.bytes_copied,
                        &result.sha256[..16],
                        &result.dest_path,
                    );
                    audit.log_ok(&result);
                    n_ok += 1;
                }

                CollectionStatus::Skipped(reason) => {
                    ui::print_skip(&def.category, &def.name, reason);
                    audit.log_skip(&result);
                    n_skip += 1;
                }

                CollectionStatus::Failed(reason) => {
                    ui::print_fail(&def.category, &def.name, reason);
                    audit.log_fail(&result);
                    n_fail += 1;
                }
            }
        }
    }

    // ── Summary ──────────────────────────────────────────────────────────────
    ui::print_summary(
        n_ok,
        n_skip,
        n_fail,
        &output_base,
        &output_base.join("collection.log"),
    );
    audit.log_summary(n_ok, n_skip, n_fail);

    // ── ZIP archive ──────────────────────────────────────────────────────────
    if cli.zip {
        let zip_path = create_zip(&output_base)
            .context("failed to create ZIP archive")?;
        ui::print_info(&format!("Archive: {}", zip_path.display()));
    }

    Ok(())
}

// ── Dry-run ───────────────────────────────────────────────────────────────────

fn run_dry(definitions: &[config::ArtifactDefinition]) {
    let mut total_paths: usize = 0;
    let mut total_bytes: u64 = 0;
    let mut unknown_size_count: usize = 0;

    for def in definitions {
        let resolved = match path_resolver::resolve_path(&def.target_path) {
            Ok(p) => p,
            Err(e) => {
                ui::print_warn(&format!("path resolution failed for '{}': {:#}", def.name, e));
                vec![]
            }
        };

        if resolved.is_empty() {
            ui::print_dry_no_match(&def.category, &def.name, &def.target_path);
        } else {
            for path in &resolved {
                let size_str = match std::fs::metadata(path) {
                    Ok(m) => {
                        let bytes = m.len();
                        total_bytes += bytes;
                        ui::format_size(bytes)
                    }
                    Err(_) => {
                        unknown_size_count += 1;
                        "?".to_owned()
                    }
                };
                ui::print_dry_collect(&def.category, &def.name, &size_str, path);
                total_paths += 1;
            }
        }
    }

    ui::print_dry_summary(definitions.len(), total_paths, total_bytes, unknown_size_count);
}

// ── ZIP archive ───────────────────────────────────────────────────────────────

/// Compress the entire `output_base` directory into `<output_base>.zip`,
/// placed in the same parent directory.
///
/// Returns the path of the created ZIP file.
fn create_zip(output_base: &Path) -> Result<PathBuf> {
    let zip_path = output_base.with_extension("zip");
    let zip_file = std::fs::File::create(&zip_path)
        .with_context(|| format!("cannot create '{}'", zip_path.display()))?;

    let mut zip = zip::ZipWriter::new(zip_file);
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);

    // Walk every file under output_base and add it with a path relative to
    // output_base's *parent* so the archive contains e.g. HOSTNAME/Registry/...
    let base_parent = output_base
        .parent()
        .unwrap_or(output_base);

    for entry in walkdir(output_base)? {
        let rel = entry
            .strip_prefix(base_parent)
            .context("failed to compute relative path for ZIP entry")?;

        // Use forward slashes inside the archive (ZIP spec).
        let zip_name = rel.to_string_lossy().replace('\\', "/");

        zip.start_file(&zip_name, options)
            .with_context(|| format!("failed to add '{zip_name}' to archive"))?;

        let data = std::fs::read(&entry)
            .with_context(|| format!("failed to read '{}' for archiving", entry.display()))?;
        zip.write_all(&data)
            .with_context(|| format!("failed to write '{zip_name}' to archive"))?;
    }

    zip.finish().context("failed to finalise ZIP archive")?;
    Ok(zip_path)
}

/// Recursively collect all *file* paths under `dir`, sorted for determinism.
fn walkdir(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    collect_files(dir, &mut files)?;
    files.sort();
    Ok(files)
}

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir)
        .with_context(|| format!("cannot read directory '{}'", dir.display()))?
    {
        let entry = entry.with_context(|| format!("error reading entry in '{}'", dir.display()))?;
        let path = entry.path();
        if path.is_dir() {
            collect_files(&path, out)?;
        } else {
            out.push(path);
        }
    }
    Ok(())
}
