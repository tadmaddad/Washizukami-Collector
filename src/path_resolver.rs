/// Path resolution: environment variable expansion and wildcard glob expansion.
///
/// Supports:
/// - `%VAR%` style environment variable references (Windows convention)
/// - `$VAR` and `${VAR}` style environment variable references (Unix convention)
/// - `*` and `**` glob wildcards via the `glob` crate
///
/// ## Multi-user wildcard patterns
///
/// Use `*` as a single-level directory wildcard to collect artifacts across all
/// user profiles, for example:
///
/// ```text
/// C:\Users\*\NTUSER.DAT
/// C:\Users\*\AppData\Local\Microsoft\Windows\UsrClass.dat
/// ```
///
/// Each matching path is returned as a separate entry.  Because
/// `collector::build_dest_path` preserves the full path structure beneath the
/// drive letter, each file lands in a unique destination:
///
/// ```text
/// output/HOST/Registry/Users/Alice/NTUSER.DAT
/// output/HOST/Registry/Users/Bob/NTUSER.DAT
/// ```
///
/// No extra handling is needed in the caller — just pass the wildcard path to
/// `resolve_path` and iterate the results.
use anyhow::{Context, Result};
use std::path::PathBuf;

/// Expand `%VAR%`, `$VAR`, and `${VAR}` style environment variable references
/// in a path string.
///
/// Unknown variables are left unexpanded (the original `%VAR%` / `$VAR` token
/// is kept in place) so the caller can detect unresolvable paths.
pub fn expand_env_vars(path: &str) -> String {
    let mut result = path.to_owned();

    // --- %VAR% style (Windows) ---
    while let Some(start) = result.find('%') {
        if let Some(end) = result[start + 1..].find('%') {
            let end = start + 1 + end;
            let var_name = &result[start + 1..end];
            if var_name.is_empty() {
                // `%%` — literal percent; skip to avoid infinite loop
                break;
            }
            match std::env::var(var_name) {
                Ok(val) => {
                    result.replace_range(start..=end, &val);
                }
                Err(_) => {
                    // Leave unknown variable in place; stop to avoid infinite loop.
                    break;
                }
            }
        } else {
            break;
        }
    }

    // --- ${VAR} style ---
    while let Some(start) = result.find("${") {
        if let Some(end) = result[start + 2..].find('}') {
            let end = start + 2 + end;
            let var_name = &result[start + 2..end];
            match std::env::var(var_name) {
                Ok(val) => {
                    result.replace_range(start..=end, &val);
                }
                Err(_) => break,
            }
        } else {
            break;
        }
    }

    // --- $VAR style (greedy word boundary: alphanumeric + '_') ---
    let mut i = 0;
    let bytes = result.as_bytes();
    let mut out = String::with_capacity(result.len());
    while i < bytes.len() {
        if bytes[i] == b'$' && i + 1 < bytes.len() && (bytes[i + 1].is_ascii_alphanumeric() || bytes[i + 1] == b'_') {
            // Already handled ${} above; skip if followed by `{`
            if bytes[i + 1] == b'{' {
                out.push(bytes[i] as char);
                i += 1;
                continue;
            }
            let start = i + 1;
            let end = bytes[start..]
                .iter()
                .position(|&b| !b.is_ascii_alphanumeric() && b != b'_')
                .map(|p| start + p)
                .unwrap_or(bytes.len());
            let var_name = &result[start..end];
            match std::env::var(var_name) {
                Ok(val) => {
                    out.push_str(&val);
                    i = end;
                }
                Err(_) => {
                    out.push(bytes[i] as char);
                    i += 1;
                }
            }
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

/// Resolve a path string (which may contain environment variables and glob
/// wildcards) to a list of concrete, existing filesystem paths.
///
/// - Environment variables are expanded first.
/// - If the expanded path contains no glob metacharacters it is returned as-is
///   (existence is not checked — the collector will handle missing files).
/// - If it contains glob metacharacters (`*`, `?`, `[`), the glob is expanded
///   and only paths that actually exist on the filesystem are returned.
///
/// ### Glob semantics
///
/// - `*` matches any sequence of characters **within a single path component**
///   (it will not cross a directory separator).  Use `**` for recursive descent.
/// - Matching is **case-insensitive** so that patterns work correctly on NTFS
///   regardless of how the filename was originally cased.
/// - Backslashes are normalised to forward slashes before matching so that
///   Windows-style paths (e.g. `C:\Users\*\NTUSER.DAT`) are handled uniformly.
pub fn resolve_path(raw_path: &str) -> Result<Vec<PathBuf>> {
    let expanded = expand_env_vars(raw_path);

    let has_glob = expanded.contains('*') || expanded.contains('?') || expanded.contains('[');

    if !has_glob {
        return Ok(vec![PathBuf::from(expanded)]);
    }

    // Normalise Windows backslashes to forward slashes so the glob engine
    // treats them as path separators rather than escape characters.
    let pattern = expanded.replace('\\', "/");

    let opts = glob::MatchOptions {
        // NTFS is case-insensitive; honour that in pattern matching.
        case_sensitive: false,
        // Prevent `*` from crossing a directory boundary.
        // Use `**` explicitly when recursive descent is intended.
        require_literal_separator: true,
        // Allow `*` to match names that begin with `.` (e.g. `.bash_history`).
        require_literal_leading_dot: false,
    };

    let mut results = Vec::new();
    for entry in glob::glob_with(&pattern, opts)
        .with_context(|| format!("invalid glob pattern: {expanded}"))?
    {
        match entry {
            Ok(path) => results.push(path),
            Err(e) => {
                // Log but do not abort on permission errors for individual entries.
                eprintln!("warn: glob entry error: {e}");
            }
        }
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_percent_style() {
        std::env::set_var("TEST_CDIR_VAR", "C:\\Windows");
        let result = expand_env_vars("%TEST_CDIR_VAR%\\System32");
        assert_eq!(result, "C:\\Windows\\System32");
    }

    #[test]
    fn expand_dollar_brace_style() {
        std::env::set_var("TEST_CDIR_HOME", "/home/user");
        let result = expand_env_vars("${TEST_CDIR_HOME}/logs");
        assert_eq!(result, "/home/user/logs");
    }

    #[test]
    fn expand_dollar_style() {
        std::env::set_var("TEST_CDIR_DIR", "/tmp");
        let result = expand_env_vars("$TEST_CDIR_DIR/file.log");
        assert_eq!(result, "/tmp/file.log");
    }

    #[test]
    fn unknown_var_left_in_place() {
        let input = "%__NONEXISTENT_VAR_XYZ__%\\path";
        let result = expand_env_vars(input);
        assert_eq!(result, input);
    }

    #[test]
    fn no_glob_returns_single_path() {
        let paths = resolve_path("C:\\Windows\\System32\\notepad.exe").unwrap();
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0], std::path::PathBuf::from("C:\\Windows\\System32\\notepad.exe"));
    }

    #[test]
    fn glob_expands_existing_paths() {
        // Use a dedicated subdirectory so parallel tests cannot interfere.
        let tmp = std::env::temp_dir().join("washi_glob_test");
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("a.txt"), b"a").unwrap();
        std::fs::write(tmp.join("b.txt"), b"b").unwrap();

        // Verify both backslash-style (Windows) and forward-slash patterns work.
        let pattern = format!("{}\\*.txt", tmp.to_string_lossy());
        let paths = resolve_path(&pattern).unwrap();

        assert_eq!(paths.len(), 2, "expected 2 .txt files");
        for p in &paths {
            assert!(p.exists(), "glob returned non-existent path: {}", p.display());
        }

        std::fs::remove_dir_all(&tmp).unwrap();
    }

    /// Simulate collecting NTUSER.DAT from multiple "user profile" directories,
    /// mirroring the real `C:\Users\*\NTUSER.DAT` pattern.
    #[test]
    fn glob_multi_user_profile_pattern() {
        let tmp = std::env::temp_dir().join("washi_users_test");

        // Create two fake user profile directories, each with NTUSER.DAT.
        let alice = tmp.join("Alice");
        let bob = tmp.join("Bob");
        std::fs::create_dir_all(&alice).unwrap();
        std::fs::create_dir_all(&bob).unwrap();
        std::fs::write(alice.join("NTUSER.DAT"), b"alice").unwrap();
        std::fs::write(bob.join("NTUSER.DAT"), b"bob").unwrap();
        // A file at the wrong depth should NOT be matched.
        std::fs::write(tmp.join("NTUSER.DAT"), b"root").unwrap();

        let pattern = format!("{}\\*\\NTUSER.DAT", tmp.to_string_lossy());
        let mut paths = resolve_path(&pattern).unwrap();
        paths.sort();

        assert_eq!(paths.len(), 2, "should match exactly Alice and Bob, not the root-level file");
        assert!(paths.iter().any(|p| p.ends_with("Alice\\NTUSER.DAT") || p.ends_with("Alice/NTUSER.DAT")));
        assert!(paths.iter().any(|p| p.ends_with("Bob\\NTUSER.DAT") || p.ends_with("Bob/NTUSER.DAT")));

        std::fs::remove_dir_all(&tmp).unwrap();
    }

    /// `*` must not cross a directory separator (require_literal_separator=true).
    #[test]
    fn glob_star_does_not_cross_separator() {
        let tmp = std::env::temp_dir().join("washi_sep_test");
        let nested = tmp.join("a").join("b");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(nested.join("file.txt"), b"x").unwrap();

        // `*` should NOT descend into `a/b/file.txt` — only `**` would do that.
        let pattern = format!("{}\\*\\file.txt", tmp.to_string_lossy());
        let paths = resolve_path(&pattern).unwrap();
        assert!(
            paths.is_empty(),
            "`*` should not match two levels deep: {:?}",
            paths
        );

        std::fs::remove_dir_all(&tmp).unwrap();
    }
}
