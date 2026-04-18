//! Modern minimal terminal UI helpers.
//!
//! All display functions live here so the rest of the codebase calls
//! semantic helpers (`ui::ok`, `ui::fail`, `ui::header`, …) rather than
//! formatting strings inline.

use colored::Colorize;
use std::io::{BufRead, Write};
use std::path::Path;

const SEP_WIDTH: usize = 56;

// ── Initialisation ────────────────────────────────────────────────────────────

/// Enable ANSI escape processing on Windows; no-op on other platforms.
pub fn init() {
    #[cfg(windows)]
    colored::control::set_virtual_terminal(true).ok();
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn sep() -> String {
    "─".repeat(SEP_WIDTH).dimmed().to_string()
}

fn config_row(label: &str, value: &str) {
    println!("  {}  {:<8}  {}", "❯".yellow(), label.dimmed(), value);
}

// ── Headers ───────────────────────────────────────────────────────────────────

/// Print the startup header for collection mode.
pub fn print_header(
    hostname: &str,
    volume_override: Option<char>,
    dry_run: bool,
    verbose: bool,
    artifact_count: usize,
    output_base: &Path,
    log_path: &Path,
) {
    let version = env!("CARGO_PKG_VERSION");
    println!(
        "\n{}  {}  {}",
        "🦅",
        "Washizukami Forensic Collector".bold().cyan(),
        format!("v{version}").dimmed(),
    );
    println!("{}", sep());

    config_row("Host", hostname);

    if let Some(v) = volume_override {
        config_row("Volume", &format!("{v}: (override)"));
    }

    let mode = if dry_run {
        "DRY RUN (no files will be copied)"
    } else if verbose {
        "Collection (verbose)"
    } else {
        "Collection"
    };
    config_row("Mode", mode);
    config_row("Targets", &format!("{artifact_count} artifact(s)"));

    if !dry_run {
        config_row("Output", &output_base.display().to_string());
        config_row("Log", &log_path.display().to_string());
    }

    println!("{}", sep());
    println!();
}

/// Print the startup header for YARA scan mode.
pub fn print_scan_header(yara_path: &Path, rules: &Path, output: &Path) {
    let version = env!("CARGO_PKG_VERSION");
    println!(
        "\n{}  {}  {}",
        "🦅",
        "Washizukami  ·  YARA Scan".bold().cyan(),
        format!("v{version}").dimmed(),
    );
    println!("{}", sep());
    config_row("Engine", &yara_path.display().to_string());
    config_row("Rules", &rules.display().to_string());
    config_row("Output", &output.display().to_string());
    println!("{}", sep());
    println!();
}

// ── Confirmation prompt ───────────────────────────────────────────────────────

/// Print `prompt`, read one line, and return `true` only for `y` / `yes`.
pub fn confirm(prompt: &str) -> bool {
    print!("  {}  {} ", "❯".yellow(), prompt);
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    if std::io::stdin().lock().read_line(&mut line).is_err() {
        return false;
    }
    matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

// ── In-progress indicator ─────────────────────────────────────────────────────

/// Print a "now collecting" line at the start of each category.
pub fn print_collecting(category: &str) {
    println!("  {}  Collecting {}…", "❯".yellow(), category.bold());
}

// ── Category-level summary row (default mode) ────────────────────────────────

/// Print a single aggregated row for one category (default non-verbose output).
///
/// Failures are not shown here — they are deferred to `print_collection_warnings`.
/// Icon and colour reflect only success vs. skip:
/// - any skip  → ⚠ yellow
/// - all ok    → ✔ green
///
/// Only call this when `n_ok + n_skip > 0`; categories with only failures are
/// omitted from the per-category output and appear in the end-of-run warning.
pub fn print_category_line(category: &str, n_ok: usize, n_skip: usize, bytes: u64) {
    let (icon, label) = if n_skip > 0 {
        ("⚠".yellow().to_string(), category.yellow().to_string())
    } else {
        ("✔".green().to_string(), category.to_string())
    };

    let total = n_ok + n_skip;
    let mut parts: Vec<String> = vec![format!("{total} file(s)")];
    if bytes > 0 {
        parts.push(format_size(bytes));
    }
    if n_skip > 0 {
        parts.push(format!("{} skipped", n_skip.to_string().yellow()));
    }

    println!("  {}  {:<12}  {}", icon, label, parts.join("  ·  "));
}

// ── End-of-run failure warning ────────────────────────────────────────────────

/// Print a warning listing every category that had at least one failure.
/// Call this after `print_summary` when `failed_categories` is non-empty.
pub fn print_collection_warnings(failed_categories: &[String], log_path: &Path) {
    let cats = failed_categories.join(", ");
    println!(
        "\n  {}  Some {} artifact(s) could not be collected.",
        "⚠".yellow(),
        cats.yellow().bold(),
    );
    println!(
        "     Check {} for details.",
        log_path.display().to_string().dimmed(),
    );
}

// ── Collection status rows ────────────────────────────────────────────────────

/// Print a successful collection row (✔).
pub fn print_ok(
    category: &str,
    name: &str,
    method_tag: &str,
    bytes: u64,
    hash_prefix: &str,
    dest_path: &Path,
) {
    println!(
        "  {}  [{method_tag}]  {}/{}  |  {}  |  {}  {}  {}",
        "✔".green(),
        category,
        name,
        format_size(bytes),
        format!("{hash_prefix}…").dimmed(),
        "→".dimmed(),
        dest_path.display().to_string().dimmed(),
    );
}

/// Print a skipped collection row (⚠).
pub fn print_skip(category: &str, name: &str, reason: &str) {
    println!(
        "  {}  {}/{}  {}  {}",
        "⚠".yellow(),
        category,
        name,
        "—".dimmed(),
        reason.dimmed(),
    );
}

/// Print a failed collection row (✖).
pub fn print_fail(category: &str, name: &str, reason: &str) {
    eprintln!(
        "  {}  {}/{}  {}  {}",
        "✖".red(),
        category,
        name,
        "—".dimmed(),
        reason.dimmed(),
    );
}

/// Print a generic warning line to stderr.
pub fn print_warn(message: &str) {
    eprintln!("  {}  {}", "⚠".yellow(), message);
}

/// Print a generic informational line.
pub fn print_info(message: &str) {
    println!("  {}  {}", "·".dimmed(), message);
}

// ── Collection summary footer ─────────────────────────────────────────────────

/// Print the collection summary footer.
pub fn print_summary(
    n_ok: usize,
    n_skip: usize,
    n_fail: usize,
    output_base: &Path,
    log_path: &Path,
) {
    println!("{}", sep());
    println!(
        "  {}  {}  ·  OK {}  ·  Skipped {}  ·  Failed {}",
        "✨",
        "Collection complete".bold(),
        n_ok.to_string().green(),
        if n_skip > 0 {
            n_skip.to_string().yellow()
        } else {
            n_skip.to_string().normal()
        },
        if n_fail > 0 {
            n_fail.to_string().red()
        } else {
            n_fail.to_string().normal()
        },
    );
    println!(
        "     {}  {}",
        "Output".dimmed(),
        output_base.display().to_string().bold(),
    );
    println!("     {}  {}", "Log   ".dimmed(), log_path.display());
    println!();
}

// ── YARA scan output ──────────────────────────────────────────────────────────

/// Print a single YARA match row.
pub fn print_scan_match(path: &Path, rules: &[String]) {
    println!(
        "  {}  {}  {}  {}",
        "⚠".yellow(),
        path.display(),
        "—".dimmed(),
        rules.join(", ").yellow(),
    );
}

/// Print the YARA scan summary footer.
pub fn print_scan_summary(n_targets: usize, n_matches: usize, zip_path: Option<&Path>) {
    println!("{}", sep());
    if n_matches == 0 {
        println!(
            "  {}  {}  ·  {} of {} target(s) matched",
            "✔".green(),
            "Scan complete".bold(),
            "0".green(),
            n_targets,
        );
    } else {
        println!(
            "  {}  {}  ·  {} of {} target(s) matched",
            "⚠".yellow(),
            "Scan complete".bold(),
            n_matches.to_string().yellow(),
            n_targets,
        );
        if let Some(zip) = zip_path {
            println!(
                "     {}  {}",
                "Archive".dimmed(),
                zip.display().to_string().bold(),
            );
        }
    }
    println!();
}

// ── Dry-run output ────────────────────────────────────────────────────────────

/// Print a "would collect" row (dry-run mode).
pub fn print_dry_collect(category: &str, name: &str, size_str: &str, path: &Path) {
    println!(
        "  {}  [{:<10}]  {:>10}  {}  {}",
        "·".dimmed(),
        category,
        size_str,
        name,
        path.display().to_string().dimmed(),
    );
}

/// Print a "no match" row (dry-run mode).
pub fn print_dry_no_match(category: &str, name: &str, pattern: &str) {
    println!(
        "  {}  [{:<10}]  {:>10}  {}  {}",
        "⚠".yellow(),
        category,
        "NO MATCH",
        name,
        pattern.dimmed(),
    );
}

/// Print the dry-run summary.
pub fn print_dry_summary(
    definition_count: usize,
    path_count: usize,
    total_bytes: u64,
    unknown_count: usize,
) {
    println!("{}", sep());
    println!(
        "  {}  Dry run  ·  {} definition(s)  ·  {} path(s) would be collected",
        "·".dimmed(),
        definition_count,
        path_count.to_string().bold(),
    );
    if total_bytes > 0 || unknown_count > 0 {
        let unknown_note = if unknown_count > 0 {
            format!(" (+{unknown_count} unknown)")
        } else {
            String::new()
        };
        println!(
            "     {}  {}{}",
            "Raw size  ".dimmed(),
            format_size(total_bytes).bold(),
            unknown_note,
        );
        let zip_low = total_bytes / 3;
        let zip_high = total_bytes / 2;
        println!(
            "     {}  {} – {}  {}",
            "ZIP size  ".dimmed(),
            format_size(zip_low),
            format_size(zip_high),
            "(50–67 % compression assumed)".dimmed(),
        );
    }
    println!();
}

// ── Size formatting ───────────────────────────────────────────────────────────

/// Format a byte count as a human-readable string (B / KB / MB / GB).
pub fn format_size(bytes: u64) -> String {
    const KB: u64 = 1_024;
    const MB: u64 = 1_024 * KB;
    const GB: u64 = 1_024 * MB;

    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} B")
    }
}
