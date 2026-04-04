use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};

// ── Public types ──────────────────────────────────────────────────────────────

/// Arguments for the `scan` subcommand.
pub struct ScanArgs {
    pub yara_path: PathBuf,
    pub rules: PathBuf,
    pub output: PathBuf,
}

/// A single file that matched one or more YARA rules.
pub struct ScanMatch {
    /// Absolute path of the matched file.
    pub path: PathBuf,
    /// Names of the rules that fired (YARA-X `identifier` field).
    pub rules: Vec<String>,
}


// ── Entry point ───────────────────────────────────────────────────────────────

/// Entry point for `washi.exe scan`.
pub fn run_scan(args: ScanArgs) {
    crate::ui::print_scan_header(&args.yara_path, &args.rules, &args.output);

    // ── Confirmation prompt ───────────────────────────────────────────────────
    if !crate::ui::confirm("Start YARA scan? [y/N]:") {
        crate::ui::print_info("Aborted.");
        return;
    }
    println!();

    // ── Collect targets ───────────────────────────────────────────────────────
    crate::ui::print_info("Collecting persistence targets…");
    let targets = collect_persistence_targets();
    if targets.is_empty() {
        crate::ui::print_info("No persistence targets found.");
        return;
    }

    // Partition into scannable (absolute path) and skipped (relative/bare name).
    let (scannable, skipped): (Vec<_>, Vec<_>) =
        targets.iter().partition(|p| p.is_absolute());

    for path in &skipped {
        crate::ui::print_warn(&format!("Not an absolute path: {}", path.display()));
    }

    if scannable.is_empty() {
        crate::ui::print_info("No scannable targets after filtering.");
        return;
    }
    crate::ui::print_info(&format!("{} target(s) to scan", scannable.len()));

    // ── Open audit log ────────────────────────────────────────────────────────
    if let Err(e) = std::fs::create_dir_all(&args.output) {
        crate::ui::print_warn(&format!("Cannot create output directory: {e}"));
        return;
    }
    let mut audit = match crate::logger::AuditLogger::new(&args.output) {
        Ok(a) => a,
        Err(e) => {
            crate::ui::print_warn(&format!("Cannot open audit log: {e:#}"));
            return;
        }
    };
    crate::ui::print_info(&format!(
        "Audit log: {}",
        args.output.join("collection.log").display()
    ));

    // ── YARA scan ─────────────────────────────────────────────────────────────
    crate::ui::print_info("Running YARA scan…");
    audit.log_scan_start(&args.yara_path, &args.rules, scannable.len());

    let matches = run_yara_scan(&args.yara_path, &args.rules, &scannable);

    for m in &matches {
        crate::ui::print_scan_match(&m.path, &m.rules);
        audit.log_scan_match(&m.path, &m.rules);
    }

    // ── Archive matched files ─────────────────────────────────────────────────
    let zip_path = args.output.join("infected.zip");
    let zip_result = if matches.is_empty() {
        None
    } else {
        match create_infected_zip(&zip_path, &matches) {
            Ok(()) => Some(zip_path.as_path()),
            Err(e) => {
                crate::ui::print_warn(&format!("infected.zip: {e:#}"));
                None
            }
        }
    };

    crate::ui::print_scan_summary(scannable.len(), matches.len(), zip_result);
    audit.log_scan_summary(matches.len(), zip_result);
}

// ── Persistence target collection ─────────────────────────────────────────────

/// Collect executable paths referenced by Windows persistence mechanisms.
///
/// Sources:
///   - HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
///   - HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
///   - C:\Windows\System32\Tasks (Task Scheduler XML, `<Command>` elements)
///
/// Each value is:
///   1. Stripped of command-line arguments (keep executable path only).
///   2. Environment-variable–expanded (`%SystemRoot%` → `C:\Windows`, etc.).
///   3. Deduplicated (case-sensitive path comparison, first-seen wins).
///
/// Returns a `Vec<PathBuf>` ready to pass to a YARA scanner.
pub fn collect_persistence_targets() -> Vec<PathBuf> {
    const RUN_KEY: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";

    let mut raw: Vec<PathBuf> = Vec::new();
    raw.extend(collect_run_key_hklm(RUN_KEY));
    raw.extend(collect_run_key_hkcu(RUN_KEY));
    raw.extend(collect_tasks(r"C:\Windows\System32\Tasks"));

    // Deduplicate while preserving insertion order.
    let mut seen: HashSet<PathBuf> = HashSet::new();
    raw.retain(|p| seen.insert(p.clone()));
    raw
}

// ── Registry — thin platform wrappers ────────────────────────────────────────

fn collect_run_key_hklm(subkey: &str) -> Vec<PathBuf> {
    #[cfg(windows)]
    {
        collect_run_key_windows(
            windows::Win32::System::Registry::HKEY_LOCAL_MACHINE,
            subkey,
        )
    }
    #[cfg(not(windows))]
    {
        let _ = subkey;
        Vec::new()
    }
}

fn collect_run_key_hkcu(subkey: &str) -> Vec<PathBuf> {
    #[cfg(windows)]
    {
        collect_run_key_windows(
            windows::Win32::System::Registry::HKEY_CURRENT_USER,
            subkey,
        )
    }
    #[cfg(not(windows))]
    {
        let _ = subkey;
        Vec::new()
    }
}

// ── Registry — Windows implementation ────────────────────────────────────────

#[cfg(windows)]
fn collect_run_key_windows(
    hive: windows::Win32::System::Registry::HKEY,
    subkey: &str,
) -> Vec<PathBuf> {
    use windows::Win32::Foundation::ERROR_NO_MORE_ITEMS;
    use windows::Win32::System::Registry::*;
    use windows::core::{PCWSTR, PWSTR};

    let mut paths = Vec::new();

    // Open the registry key (read-only).
    let subkey_w: Vec<u16> = subkey.encode_utf16().chain(std::iter::once(0)).collect();
    let mut hkey = HKEY::default();
    let res = unsafe {
        RegOpenKeyExW(
            hive,
            PCWSTR(subkey_w.as_ptr()),
            None,   // uloptions — Option<u32> in windows 0.61
            KEY_READ,
            &mut hkey,
        )
    };
    if res.ok().is_err() {
        return paths;
    }

    // Enumerate every value entry.
    let mut index = 0u32;
    loop {
        // name_len is in UTF-16 code units, NOT bytes.
        let mut name_buf = vec![0u16; 16_384];
        let mut name_len = name_buf.len() as u32;
        // lpType is *mut u32 in windows 0.61 (REG_VALUE_TYPE is a u32 newtype).
        let mut data_type_raw: u32 = 0;
        // Data buffer sized for the largest practical Run key value.
        let mut data_buf = vec![0u8; 65_536];
        let mut data_len = data_buf.len() as u32;

        let res = unsafe {
            RegEnumValueW(
                hkey,
                index,
                Some(PWSTR(name_buf.as_mut_ptr())),
                &mut name_len,
                None,
                Some(&mut data_type_raw as *mut u32),
                Some(data_buf.as_mut_ptr()),
                Some(&mut data_len),
            )
        };

        if res == ERROR_NO_MORE_ITEMS {
            break;
        }
        if res.ok().is_err() {
            index += 1;
            continue;
        }

        // Only process string values (REG_SZ == 1, REG_EXPAND_SZ == 2).
        if REG_VALUE_TYPE(data_type_raw) == REG_SZ
            || REG_VALUE_TYPE(data_type_raw) == REG_EXPAND_SZ
        {
            // data_len is in bytes; convert to UTF-16 code units.
            let wchar_count = data_len as usize / 2;
            let wchars: Vec<u16> = data_buf[..wchar_count * 2]
                .chunks_exact(2)
                .map(|b| u16::from_le_bytes([b[0], b[1]]))
                .collect();
            let value_str = String::from_utf16_lossy(&wchars);
            let value_str = value_str.trim_end_matches('\0');

            if let Some(exe) = extract_exe_path(value_str) {
                let expanded = expand_env_vars(&exe);
                if !expanded.is_empty() {
                    paths.push(PathBuf::from(expanded));
                }
            }
        }

        index += 1;
    }

    unsafe {
        let _ = RegCloseKey(hkey);
    }
    paths
}

// ── Task Scheduler XML ────────────────────────────────────────────────────────

/// Walk `C:\Windows\System32\Tasks` recursively and extract `<Command>` paths.
///
/// Task Scheduler stores tasks as XML files with no file extension.
/// Each `<Exec>` action contains a `<Command>` element with the executable.
fn collect_tasks(tasks_dir: &str) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let dir = Path::new(tasks_dir);
    if dir.is_dir() {
        collect_tasks_recursive(dir, &mut paths);
    }
    paths
}

fn collect_tasks_recursive(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_tasks_recursive(&path, out);
        } else {
            // Task Scheduler XML files are UTF-16 LE with BOM (0xFF 0xFE).
            // read_to_string() assumes UTF-8 and silently fails on them,
            // so read raw bytes and decode manually.
            if let Ok(bytes) = std::fs::read(&path) {
                if let Some(content) = decode_task_xml(&bytes) {
                    extract_commands_from_xml(&content, out);
                }
            }
        }
    }
}

/// Decode a Task Scheduler XML file.
///
/// Returns `Some(String)` for both UTF-16 LE (BOM `FF FE`) and UTF-8 content.
/// Returns `None` if the bytes cannot be interpreted as either encoding.
fn decode_task_xml(bytes: &[u8]) -> Option<String> {
    if bytes.starts_with(&[0xFF, 0xFE]) {
        // UTF-16 LE with BOM — skip the 2-byte BOM, then decode.
        let words: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .collect();
        Some(String::from_utf16_lossy(&words).to_string())
    } else {
        // Fall back to UTF-8 (covers ASCII task files and future UTF-8 tasks).
        String::from_utf8(bytes.to_vec()).ok()
    }
}

/// Extract every `<Command>…</Command>` value from a Task Scheduler XML string.
///
/// Unlike Run key values, `<Command>` contains only the executable path —
/// arguments live in a separate `<Arguments>` element.  We therefore do NOT
/// split on whitespace here; we only strip surrounding quotes if present.
fn extract_commands_from_xml(xml: &str, out: &mut Vec<PathBuf>) {
    let mut rest = xml;
    while let Some(start) = rest.find("<Command>") {
        rest = &rest[start + "<Command>".len()..];
        if let Some(end) = rest.find("</Command>") {
            let cmd = rest[..end].trim();
            if !cmd.is_empty() {
                // Strip surrounding quotes only — do NOT split on spaces.
                let unquoted = cmd.trim_matches('"');
                if !unquoted.is_empty() {
                    let expanded = expand_env_vars(unquoted);
                    if !expanded.is_empty() {
                        out.push(PathBuf::from(expanded));
                    }
                }
            }
            rest = &rest[end + "</Command>".len()..];
        } else {
            break;
        }
    }
}

// ── Path helpers ──────────────────────────────────────────────────────────────

/// Extract the executable path from a Run-key value or `<Command>` string.
///
/// Run key values often carry arguments after the path:
///   - `"C:\Program Files\App\app.exe" --silent`  →  `C:\Program Files\App\app.exe`
///   - `C:\Windows\system32\ctfmon.exe`            →  `C:\Windows\system32\ctfmon.exe`
///   - `%SystemRoot%\system32\foo.exe /arg`        →  `%SystemRoot%\system32\foo.exe`
#[cfg(windows)]
fn extract_exe_path(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    let path = if let Some(rest) = value.strip_prefix('"') {
        // Quoted path: take everything up to the closing quote.
        &rest[..rest.find('"')?]
    } else {
        // Unquoted: take up to the first whitespace character.
        value.split_ascii_whitespace().next()?
    };
    if path.is_empty() {
        None
    } else {
        Some(path.to_owned())
    }
}

/// Expand environment variable references (`%VAR%`) to their current values.
///
/// Falls back to the original string on failure.
fn expand_env_vars(s: &str) -> String {
    #[cfg(windows)]
    {
        expand_env_vars_windows(s)
    }
    #[cfg(not(windows))]
    {
        s.to_owned()
    }
}

#[cfg(windows)]
fn expand_env_vars_windows(s: &str) -> String {
    use windows::Win32::System::Environment::ExpandEnvironmentStringsW;
    use windows::core::PCWSTR;

    // windows 0.61: ExpandEnvironmentStringsW(src, lpdst: Option<&mut [u16]>) -> u32
    // Passing None returns the required buffer size (including NUL).
    let src_w: Vec<u16> = s.encode_utf16().chain(std::iter::once(0)).collect();

    let needed = unsafe {
        ExpandEnvironmentStringsW(PCWSTR(src_w.as_ptr()), None)
    } as usize;
    if needed == 0 {
        return s.to_owned();
    }

    let mut dst_w = vec![0u16; needed];
    let written = unsafe {
        ExpandEnvironmentStringsW(PCWSTR(src_w.as_ptr()), Some(&mut dst_w))
    } as usize;
    if written == 0 {
        return s.to_owned();
    }

    // `written` includes the NUL terminator — exclude it.
    let len = written.saturating_sub(1);
    String::from_utf16_lossy(&dst_w[..len])
}

// ── YARA execution ────────────────────────────────────────────────────────────

/// Invoke `yr scan --json <rules> <targets…>` and parse the results.
///
/// YARA-X exit codes:
///   0 — scan complete, no matches
///   1 — scan complete, one or more matches found
///   other — error (missing rules file, I/O error, etc.)
///
/// Only files that matched appear in the JSON output; files with no match
/// are absent.  An empty `Vec` is returned on error or when nothing matched.
fn run_yara_scan(yara_path: &Path, rules: &Path, targets: &[&PathBuf]) -> Vec<ScanMatch> {
    use std::process::Command;

    // yr scan accepts only a single TARGET_PATH, so write all paths to a temp
    // file and pass it via --scan-list (one absolute path per line).
    let list_path = std::env::temp_dir().join("washi_scan_list.txt");
    {
        let content = targets
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("\n");
        if let Err(e) = std::fs::write(&list_path, content) {
            eprintln!("[FAIL] Could not write scan list: {e}");
            return Vec::new();
        }
    }

    let output = Command::new(yara_path)
        .arg("scan")
        .arg("--output-format").arg("json")
        .arg("--scan-list")
        .arg(rules)
        .arg(&list_path)
        .output();

    // Clean up temp file regardless of outcome.
    let _ = std::fs::remove_file(&list_path);

    let output = match output {
        Ok(o) => o,
        Err(e) => {
            eprintln!("[FAIL] Could not launch yr.exe: {e}");
            return Vec::new();
        }
    };

    // Exit code 0 = no matches, 1 = matches found — both are successes.
    let code = output.status.code().unwrap_or(-1);
    if code != 0 && code != 1 {
        eprintln!("[FAIL] yr.exe exited with code {code}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.trim().is_empty() {
            eprintln!("[FAIL] yr.exe stderr: {}", stderr.trim());
        }
        return Vec::new();
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.trim().is_empty() {
        return Vec::new();
    }

    let results = parse_yara_json(&stdout);
    if results.is_empty() && !stdout.trim().is_empty() {
        let snippet: String = stdout.chars().take(300).collect();
        eprintln!("[WARN] yr.exe output could not be parsed, snippet: {snippet}");
    }
    results
}

// ── infected.zip ──────────────────────────────────────────────────────────────

/// Compress all matched files into `infected.zip`.
///
/// NOTE: AES-256 password encryption is not applied here because the `aes`
/// crate's build script is blocked by the WDAC policy on this build machine.
/// The archive follows the `infected.zip` naming convention used by malware
/// repositories; password protection can be layered on later once the WDAC
/// exemption is in place.
///
/// ZIP entry paths use the absolute file path with the drive colon stripped,
/// avoiding collisions between files from different drives:
///   `C:\Windows\system32\foo.exe`  →  `C/Windows/system32/foo.exe`
fn create_infected_zip(zip_path: &Path, matches: &[ScanMatch]) -> anyhow::Result<()> {
    let file = std::fs::File::create(zip_path)
        .map_err(|e| anyhow::anyhow!("cannot create '{}': {e}", zip_path.display()))?;

    let mut zip = zip::ZipWriter::new(file);
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);

    for m in matches {
        // Build a collision-free in-archive path from the absolute file path.
        let raw = m.path.to_string_lossy().replace(':', "").replace('\\', "/");
        let entry_name = raw.trim_start_matches('/').to_owned();

        zip.start_file(&entry_name, options)
            .map_err(|e| anyhow::anyhow!("zip entry '{}': {e}", entry_name))?;

        match std::fs::read(&m.path) {
            Ok(data) => zip
                .write_all(&data)
                .map_err(|e| anyhow::anyhow!("write '{}': {e}", entry_name))?,
            Err(e) => {
                // Log and skip unreadable files rather than aborting the archive.
                eprintln!("[WARN] Cannot read '{}': {e}", m.path.display());
            }
        }
    }

    zip.finish().map_err(|e| anyhow::anyhow!("finalise zip: {e}"))?;
    Ok(())
}

// ── YARA-X JSON parser ────────────────────────────────────────────────────────

/// Parse the YARA-X 1.14.0 `--output-format json` output into `ScanMatch` entries.
///
/// Actual format (one object, not an array):
/// ```json
/// { "version": "1.14.0", "matches": [{"rule": "rule_name", "file": "C:\\..."}, ...] }
/// ```
/// Each entry in `matches` is one (rule, file) pair.
/// Multiple entries sharing the same `"file"` are grouped into one `ScanMatch`.
fn parse_yara_json(json: &str) -> Vec<ScanMatch> {
    // Collect all (file, rule) pairs by scanning for "rule" then "file" in sequence.
    let mut pairs: Vec<(String, String)> = Vec::new();
    let mut cursor = json;

    while let Some((rule_name, after_rule)) = extract_json_string_for_key(cursor, "\"rule\"") {
        cursor = after_rule;
        if let Some((file_path, after_file)) = extract_json_string_for_key(cursor, "\"file\"") {
            pairs.push((file_path, rule_name));
            cursor = after_file;
        }
    }

    // Group by file, preserving order of first appearance.
    let mut seen: HashSet<String> = HashSet::new();
    let mut results: Vec<ScanMatch> = Vec::new();

    for (file, _) in &pairs {
        if seen.insert(file.clone()) {
            let rules: Vec<String> = pairs
                .iter()
                .filter(|(f, _)| f == file)
                .map(|(_, r)| r.clone())
                .collect();
            results.push(ScanMatch {
                path: PathBuf::from(file),
                rules,
            });
        }
    }

    results
}

/// Find `key` in `json`, then extract and return the JSON string value that
/// follows it, along with the remaining input after the closing quote.
fn extract_json_string_for_key<'a>(
    json: &'a str,
    key: &str,
) -> Option<(String, &'a str)> {
    let key_pos = json.find(key)?;
    let after_key = &json[key_pos + key.len()..];
    // Skip whitespace and the colon separator.
    let after_colon = after_key.trim_start_matches(|c: char| c == ':' || c.is_ascii_whitespace());
    // Expect an opening double-quote.
    let after_open = after_colon.strip_prefix('"')?;
    scan_json_string(after_open)
}

/// Scan a JSON string starting just after the opening `"`.
///
/// Returns the decoded string and a reference to the input after the closing `"`.
fn scan_json_string(s: &str) -> Option<(String, &str)> {
    let mut result = String::new();
    let mut chars = s.char_indices();
    loop {
        let (i, ch) = chars.next()?;
        match ch {
            '"' => return Some((result, &s[i + 1..])),
            '\\' => match chars.next()?.1 {
                '"' => result.push('"'),
                '\\' => result.push('\\'),
                '/' => result.push('/'),
                'n' => result.push('\n'),
                'r' => result.push('\r'),
                't' => result.push('\t'),
                c => result.push(c),
            },
            c => result.push(c),
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_quoted_path_strips_args() {
        let v = r#""C:\Program Files\App\app.exe" --silent"#;
        assert_eq!(
            extract_exe_path(v).as_deref(),
            Some(r"C:\Program Files\App\app.exe")
        );
    }

    #[test]
    fn extract_unquoted_path_strips_args() {
        let v = r"C:\Windows\system32\ctfmon.exe /arg";
        assert_eq!(
            extract_exe_path(v).as_deref(),
            Some(r"C:\Windows\system32\ctfmon.exe")
        );
    }

    #[test]
    fn extract_path_no_args() {
        let v = r"C:\Windows\system32\ctfmon.exe";
        assert_eq!(
            extract_exe_path(v).as_deref(),
            Some(r"C:\Windows\system32\ctfmon.exe")
        );
    }

    #[test]
    fn extract_empty_returns_none() {
        assert_eq!(extract_exe_path(""), None);
        assert_eq!(extract_exe_path("   "), None);
    }

    #[test]
    fn extract_commands_from_xml_basic() {
        let xml = r#"
            <Task>
              <Actions>
                <Exec>
                  <Command>C:\Windows\system32\foo.exe</Command>
                  <Arguments>/silent</Arguments>
                </Exec>
              </Actions>
            </Task>
        "#;
        let mut out = Vec::new();
        extract_commands_from_xml(xml, &mut out);
        assert_eq!(out, vec![PathBuf::from(r"C:\Windows\system32\foo.exe")]);
    }

    #[test]
    fn extract_commands_from_xml_multiple() {
        let xml = r#"
            <Command>C:\a.exe</Command>
            <Command>C:\b.exe</Command>
        "#;
        let mut out = Vec::new();
        extract_commands_from_xml(xml, &mut out);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn collect_persistence_targets_deduplicates() {
        // Smoke-test: must not panic, and the result must have no duplicates.
        // (On a real system this may return entries; on CI it returns an empty vec.)
        let targets = collect_persistence_targets();
        let deduped: HashSet<_> = targets.iter().collect();
        assert_eq!(targets.len(), deduped.len());
    }
}
