//! External tool integration.
//!
//! Locates and invokes third-party binaries (e.g. winpmem) placed in the
//! `tools/` subdirectory alongside the executable.  All invocations are
//! logged to the audit log via [`AuditLogger`].

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

use crate::logger::AuditLogger;

/// Search priority for winpmem binary names (case-insensitive stem match).
/// Earlier entries win when multiple candidates are found.
const WINPMEM_PRIORITY: &[&str] = &["winpmem_x64", "winpmem_x32", "winpmem"];

/// Find a winpmem binary in `<exe_dir>/tools/`.
///
/// Accepts any filename whose stem starts with `winpmem` (case-insensitive).
/// When multiple candidates exist, the one whose stem appears earliest in
/// [`WINPMEM_PRIORITY`] is preferred; otherwise the first found is used.
fn find_winpmem(exe_dir: &Path) -> Option<PathBuf> {
    let tools_dir = exe_dir.join("tools");

    let mut candidates: Vec<PathBuf> = std::fs::read_dir(&tools_dir)
        .ok()?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .and_then(|s| s.to_str())
                .map(|s| s.eq_ignore_ascii_case("exe"))
                .unwrap_or(false)
                && p.file_stem()
                    .and_then(|s| s.to_str())
                    .map(|s| s.to_ascii_lowercase().starts_with("winpmem"))
                    .unwrap_or(false)
        })
        .collect();

    if candidates.is_empty() {
        return None;
    }

    // Sort by priority list; unknown names go last.
    candidates.sort_by_key(|p| {
        let stem = p
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        WINPMEM_PRIORITY
            .iter()
            .position(|&prio| stem == prio)
            .unwrap_or(WINPMEM_PRIORITY.len())
    });

    candidates.into_iter().next()
}

/// Run the winpmem binary found in `<exe_dir>/tools/` to produce a memory
/// dump under `output_base`.
///
/// If no `winpmem*.exe` is found, a warning is logged and the function
/// returns `Ok(())` so the rest of the collection run is unaffected.
///
/// The dump is written to `<output_base>/memory.dmp`.
pub fn run_winpmem(exe_dir: &Path, output_base: &Path, audit: &mut AuditLogger) -> Result<()> {
    let winpmem = match find_winpmem(exe_dir) {
        Some(p) => p,
        None => {
            let msg = format!(
                "--mem specified but no winpmem*.exe found in '{}' — skipping memory dump",
                exe_dir.join("tools").display()
            );
            eprintln!("[WARN] {msg}");
            audit.log_warn(&msg);
            return Ok(());
        }
    };

    let dump_path = output_base.join("memory.dmp");
    audit.log_tool_start(&winpmem, &dump_path);
    println!("[*] Memory dump : {} -> {}", winpmem.display(), dump_path.display());

    let status = std::process::Command::new(&winpmem)
        .arg(&dump_path)
        .status()
        .with_context(|| format!("failed to launch '{}'", winpmem.display()))?;

    let code = status.code().unwrap_or(-1);
    if status.success() {
        println!("[OK][winpmem] memory dump complete (exit {code})");
        audit.log_tool_ok(&winpmem, code);
    } else {
        eprintln!("[FAIL] winpmem exited with code {code}");
        audit.log_tool_fail(&winpmem, code);
    }

    Ok(())
}
