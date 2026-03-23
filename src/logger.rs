//! File-based audit logger.
//!
//! Writes one line per event to `<output_base>/collection.log` in the format:
//!
//! ```text
//! [2026-03-21T10:30:00+09:00] [OK   ] [NTFS        ] C:\Windows\...\SAM -> output\...\SAM (262144 bytes, SHA256: abcd1234...)
//! [2026-03-21T10:30:01+09:00] [SKIP ] [-           ] C:\path\missing — file not found
//! [2026-03-21T10:30:02+09:00] [FAIL ] [File        ] C:\path\locked — <error>
//! [2026-03-21T10:30:03+09:00] [WARN ] [-           ] path resolution failed for 'X': ...
//! ```

use anyhow::{Context, Result};
use chrono::Local;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;
use std::ffi::OsStr;

use crate::collector::{CollectionResult, CollectionStatus};
use crate::config::CollectionMethod;

/// Writes structured audit entries to `<output_base>/collection.log`.
pub struct AuditLogger {
    writer: BufWriter<File>,
}

impl AuditLogger {
    /// Open (or create) `<output_base>/collection.log` for appending.
    pub fn new(output_base: &Path) -> Result<Self> {
        std::fs::create_dir_all(output_base)
            .with_context(|| format!("cannot create output directory '{}'", output_base.display()))?;

        let log_path = output_base.join("collection.log");
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .with_context(|| format!("cannot open log file '{}'", log_path.display()))?;

        Ok(Self {
            writer: BufWriter::new(file),
        })
    }

    /// Log a successful collection.
    pub fn log_ok(&mut self, result: &CollectionResult) {
        let method = match (&result.method_used, result.fell_back) {
            (_, true) => "NTFS-fallback",
            (CollectionMethod::NTFS, _) => "NTFS",
            (CollectionMethod::File, _) => "File",
        };
        let line = format!(
            "{} [OK   ] [{:<12}] {} -> {} ({} bytes, SHA256: {})",
            timestamp(),
            method,
            result.source_path.display(),
            result.dest_path.display(),
            result.bytes_copied,
            result.sha256,
        );
        self.write_line(&line);
    }

    /// Log a skipped artifact (source file absent — not an error).
    pub fn log_skip(&mut self, result: &CollectionResult) {
        let reason = match &result.status {
            CollectionStatus::Skipped(r) => r.as_str(),
            _ => "skipped",
        };
        let line = format!(
            "{} [SKIP ] [{:<12}] {} — {}",
            timestamp(),
            "-",
            result.source_path.display(),
            reason,
        );
        self.write_line(&line);
    }

    /// Log a failed collection attempt.
    pub fn log_fail(&mut self, result: &CollectionResult) {
        let reason = match &result.status {
            CollectionStatus::Failed(r) => r.as_str(),
            _ => "failed",
        };
        let line = format!(
            "{} [FAIL ] [{:<12}] {} — {}",
            timestamp(),
            "-",
            result.source_path.display(),
            reason,
        );
        self.write_line(&line);
    }

    /// Log a warning not tied to a specific CollectionResult (e.g. path
    /// resolution errors).
    pub fn log_warn(&mut self, msg: &str) {
        let line = format!("{} [WARN ] [{:<12}] {}", timestamp(), "-", msg);
        self.write_line(&line);
    }

    /// Log the final summary line.
    pub fn log_summary(&mut self, n_ok: usize, n_skip: usize, n_fail: usize) {
        let line = format!(
            "{} [INFO ] [{:<12}] Complete — OK: {}  Skipped: {}  Failed: {}",
            timestamp(),
            "-",
            n_ok,
            n_skip,
            n_fail,
        );
        self.write_line(&line);
    }

    /// Log the start of a YARA scan.
    pub fn log_scan_start(&mut self, yara_path: &Path, rules: &Path, target_count: usize) {
        let line = format!(
            "{} [SCAN ] [{:<12}] Starting scan — engine: {}  rules: {}  targets: {}",
            timestamp(),
            tool_name(yara_path),
            yara_path.display(),
            rules.display(),
            target_count,
        );
        self.write_line(&line);
    }

    /// Log a single YARA rule match.
    pub fn log_scan_match(&mut self, path: &std::path::Path, rules: &[String]) {
        let line = format!(
            "{} [MATCH] [{:<12}] {} — {}",
            timestamp(),
            "yara",
            path.display(),
            rules.join(", "),
        );
        self.write_line(&line);
    }

    /// Log the scan summary (matches found, archive path).
    pub fn log_scan_summary(&mut self, matched: usize, archive: Option<&Path>) {
        let archive_note = match archive {
            Some(p) => format!("  archive: {}", p.display()),
            None => String::new(),
        };
        let line = format!(
            "{} [SCAN ] [{:<12}] Complete — matched: {}{}",
            timestamp(),
            "-",
            matched,
            archive_note,
        );
        self.write_line(&line);
    }

    /// Log the start of an external tool invocation.
    pub fn log_tool_start(&mut self, tool: &Path, output: &Path) {
        let name = tool_name(tool);
        let line = format!(
            "{} [TOOL ] [{:<12}] Starting: {} -> {}",
            timestamp(), name, tool.display(), output.display(),
        );
        self.write_line(&line);
    }

    /// Log a successful external tool exit.
    pub fn log_tool_ok(&mut self, tool: &Path, exit_code: i32) {
        let name = tool_name(tool);
        let line = format!(
            "{} [TOOL ] [{:<12}] Success (exit {}): {}",
            timestamp(), name, exit_code, tool.display(),
        );
        self.write_line(&line);
    }

    /// Log a failed external tool exit.
    pub fn log_tool_fail(&mut self, tool: &Path, exit_code: i32) {
        let name = tool_name(tool);
        let line = format!(
            "{} [TOOL ] [{:<12}] Failed  (exit {}): {}",
            timestamp(), name, exit_code, tool.display(),
        );
        self.write_line(&line);
    }

    fn write_line(&mut self, line: &str) {
        // Errors writing to the log are silently ignored so they never
        // interrupt the collection run itself.
        let _ = writeln!(self.writer, "{line}");
        let _ = self.writer.flush();
    }
}

fn timestamp() -> String {
    Local::now().format("[%Y-%m-%dT%H:%M:%S%z]").to_string()
}

fn tool_name(tool: &Path) -> &str {
    tool.file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("tool")
}
