/// Artifact collection engine.
///
/// Defines the [`Collector`] trait, two concrete implementations
/// ([`StandardCollector`] and [`RawCollector`]), and the top-level
/// [`collect_artifact`] dispatcher that applies the File → NTFS fallback
/// strategy described in `CLAUDE.md`.
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufWriter, Read, Write};
use std::path::{Component, Path, PathBuf, Prefix};

use crate::config::{ArtifactDefinition, CollectionMethod};
use crate::ntfs_reader::NtfsReader;

// ── Result types ─────────────────────────────────────────────────────────────

/// Outcome of a single artifact collection attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CollectionStatus {
    /// File was copied successfully (check [`CollectionResult::fell_back`] for
    /// whether the NTFS fallback was used).
    Success,
    /// The source file was not present at collection time; not an error.
    Skipped(String),
    /// Collection failed even after any applicable fallback.
    Failed(String),
}

/// Metadata produced by a single artifact collection attempt.
#[derive(Debug, Clone)]
pub struct CollectionResult {
    /// Absolute path on the source system.
    pub source_path: PathBuf,
    /// Where the artifact was written.
    pub dest_path: PathBuf,
    /// Number of bytes written (0 when not Success).
    pub bytes_copied: u64,
    /// Lowercase hex SHA-256 digest of the extracted bytes.
    /// Empty when status is Skipped or Failed.
    pub sha256: String,
    /// Collection method that produced the data.
    pub method_used: CollectionMethod,
    /// True when a `File`-method artifact fell back to NTFS raw read
    /// due to an access/sharing error.
    pub fell_back: bool,
    pub status: CollectionStatus,
}

// ── Collector trait ───────────────────────────────────────────────────────────

/// Abstraction over how a single file is transferred from `source` to `dest`.
///
/// Implementations must:
/// - Create all parent directories of `dest` before writing.
/// - Never modify `source` (forensic read-only constraint).
/// - Return an `Err` that carries the original [`std::io::Error`] so that the
///   dispatcher can inspect the OS error code for the fallback decision.
pub trait Collector {
    fn collect(&mut self, source: &Path, dest: &Path) -> Result<CollectionResult>;
}

// ── StandardCollector ─────────────────────────────────────────────────────────

/// Copies files through the normal OS file-system API.
///
/// Will fail with a sharing violation (`ERROR_SHARING_VIOLATION`, OS error 32)
/// or permission denied error for actively locked files such as registry hives
/// and event logs.  The dispatcher treats these as trigger conditions for the
/// [`RawCollector`] fallback.
pub struct StandardCollector;

impl Collector for StandardCollector {
    fn collect(&mut self, source: &Path, dest: &Path) -> Result<CollectionResult> {
        ensure_parent(dest)?;

        // Open source — propagate the raw IO error so the dispatcher can
        // inspect io::Error::kind() / raw_os_error().
        let mut src = File::open(source)
            .with_context(|| format!("cannot open '{}'", source.display()))?;

        let out = File::create(dest)
            .with_context(|| format!("cannot create '{}'", dest.display()))?;
        let mut writer = BufWriter::new(out);

        let (bytes, sha256) = hash_and_copy(&mut src, &mut writer)?;
        writer.flush().context("flush error")?;

        Ok(CollectionResult {
            source_path: source.to_owned(),
            dest_path: dest.to_owned(),
            bytes_copied: bytes,
            sha256,
            method_used: CollectionMethod::File,
            fell_back: false,
            status: CollectionStatus::Success,
        })
    }
}

// ── RawCollector ──────────────────────────────────────────────────────────────

/// Extracts files via direct MFT traversal, bypassing OS file locks entirely.
///
/// [`NtfsReader`] instances are cached by volume string (e.g. `"\\.\C:"`) so
/// the MFT boot-sector parse only happens once per volume per run.
pub struct RawCollector {
    readers: HashMap<String, NtfsReader>,
}

impl RawCollector {
    pub fn new() -> Self {
        Self {
            readers: HashMap::new(),
        }
    }
}

impl Collector for RawCollector {
    fn collect(&mut self, source: &Path, dest: &Path) -> Result<CollectionResult> {
        let (volume, relative) = extract_volume(source)?;

        // Get or open the volume reader (cached).
        let reader = match self.readers.entry(volume.clone()) {
            std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
            std::collections::hash_map::Entry::Vacant(e) => {
                let r = NtfsReader::open(&volume)
                    .with_context(|| format!("cannot open NTFS volume '{volume}'"))?;
                e.insert(r)
            }
        };

        ensure_parent(dest)?;

        let bytes = reader
            .extract_file(&relative, None, dest)
            .with_context(|| format!("NTFS extract failed for '{}'", source.display()))?;

        // Hash the written output (single additional pass; keeps NtfsReader API unchanged).
        let sha256 = sha256_of_file(dest)?;

        Ok(CollectionResult {
            source_path: source.to_owned(),
            dest_path: dest.to_owned(),
            bytes_copied: bytes,
            sha256,
            method_used: CollectionMethod::NTFS,
            fell_back: false,
            status: CollectionStatus::Success,
        })
    }
}

impl RawCollector {
    /// Extract a named Alternate Data Stream via NTFS raw read.
    ///
    /// Used for `$SECURE:$SDS`, `$UsnJrnl:$J`, and any other ADS artifacts.
    /// There is no `File`-method fallback for ADS — they are only reachable
    /// through the raw NTFS path.
    pub fn collect_with_stream(
        &mut self,
        source: &Path,
        stream: &str,
        dest: &Path,
    ) -> Result<CollectionResult> {
        let (volume, relative) = extract_volume(source)?;

        let reader = match self.readers.entry(volume.clone()) {
            std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
            std::collections::hash_map::Entry::Vacant(e) => {
                let r = NtfsReader::open(&volume)
                    .with_context(|| format!("cannot open NTFS volume '{volume}'"))?;
                e.insert(r)
            }
        };

        ensure_parent(dest)?;

        let bytes = reader
            .extract_file(&relative, Some(stream), dest)
            .with_context(|| {
                format!("NTFS stream extract failed for '{}:{}'", source.display(), stream)
            })?;

        let sha256 = sha256_of_file(dest)?;

        Ok(CollectionResult {
            source_path: source.to_owned(),
            dest_path: dest.to_owned(),
            bytes_copied: bytes,
            sha256,
            method_used: CollectionMethod::NTFS,
            fell_back: false,
            status: CollectionStatus::Success,
        })
    }
}

// ── Dispatcher ────────────────────────────────────────────────────────────────

/// Collect a single resolved file path according to its artifact definition.
///
/// Fallback behaviour:
/// - `CollectionMethod::NTFS` → [`RawCollector`] directly; no fallback.
/// - `CollectionMethod::File` → [`StandardCollector`] first.  On any
///   access/sharing error, automatically retries with [`RawCollector`] and
///   sets [`CollectionResult::fell_back`] to `true`.
///
/// This function **never panics**.  All errors are surfaced through
/// [`CollectionResult::status`].
pub fn collect_artifact(
    def: &ArtifactDefinition,
    source_path: &Path,
    output_base: &Path,
    raw_collector: &mut RawCollector,
) -> CollectionResult {
    let dest = build_dest(output_base, &def.category, source_path, def.stream.as_deref());

    // Alternate Data Stream artifacts can only be read via NTFS raw access.
    if let Some(stream) = &def.stream {
        return raw_collector
            .collect_with_stream(source_path, stream, &dest)
            .unwrap_or_else(|e| into_failed_result(source_path, &dest, CollectionMethod::NTFS, e));
    }

    match def.method {
        CollectionMethod::NTFS => raw_collector
            .collect(source_path, &dest)
            .unwrap_or_else(|e| into_failed_result(source_path, &dest, CollectionMethod::NTFS, e)),

        CollectionMethod::File => {
            let mut std_col = StandardCollector;
            match std_col.collect(source_path, &dest) {
                Ok(r) => r,

                // Access denied or sharing violation: try NTFS raw read.
                Err(ref e) if is_access_error(e) => {
                    match raw_collector.collect(source_path, &dest) {
                        Ok(mut r) => {
                            r.fell_back = true;
                            r
                        }
                        Err(e2) => into_failed_result(
                            source_path,
                            &dest,
                            CollectionMethod::NTFS,
                            e2,
                        ),
                    }
                }

                Err(e) => into_failed_result(source_path, &dest, CollectionMethod::File, e),
            }
        }
    }
}

// ── Path helpers ──────────────────────────────────────────────────────────────

/// Build the destination path: `{output_base}/{category}/{path_without_drive}`.
///
/// `C:\Windows\System32\config\SAM` with category `Registry`
/// → `output/HOST/Registry/Windows/System32/config/SAM`
pub fn build_dest_path(output_base: &Path, category: &str, source_path: &Path) -> PathBuf {
    let relative: PathBuf = source_path
        .components()
        .filter_map(|c| match c {
            Component::Normal(s) => Some(PathBuf::from(s)),
            _ => None,
        })
        .collect();

    output_base.join(category).join(relative)
}

/// Build the destination path, appending the stream name suffix when the
/// artifact targets an Alternate Data Stream.
///
/// `C:\$Extend\$UsnJrnl` with stream `"$J"`
/// → `output/HOST/NTFS/$Extend/$UsnJrnl_J`
fn build_dest(
    output_base: &Path,
    category: &str,
    source_path: &Path,
    stream: Option<&str>,
) -> PathBuf {
    if let Some(s) = stream {
        let base = source_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");
        // Strip leading '$' from stream name to keep the suffix readable
        // while remaining a valid Windows filename component.
        let suffix = s.trim_start_matches('$');
        let new_name = format!("{}_{}", base, suffix);
        let modified = source_path.with_file_name(new_name);
        build_dest_path(output_base, category, &modified)
    } else {
        build_dest_path(output_base, category, source_path)
    }
}

/// Split a Windows absolute path into `(volume_string, relative_path)`.
///
/// `"C:\Windows\System32\config\SAM"` → `("\\.\C:", "Windows\System32\config\SAM")`
fn extract_volume(path: &Path) -> Result<(String, PathBuf)> {
    let mut comps = path.components();

    let drive_char = match comps.next() {
        Some(Component::Prefix(p)) => match p.kind() {
            Prefix::Disk(c) | Prefix::VerbatimDisk(c) => c as char,
            _ => bail!("unsupported path prefix in '{}'", path.display()),
        },
        _ => bail!(
            "path '{}' has no drive-letter prefix — cannot determine NTFS volume",
            path.display()
        ),
    };

    // Skip the root-directory separator if present.
    let mut rest = comps.peekable();
    if matches!(rest.peek(), Some(Component::RootDir)) {
        let _ = rest.next();
    }

    let relative: PathBuf = rest.collect();
    let volume = format!("\\\\.\\{}:", drive_char.to_ascii_uppercase());

    Ok((volume, relative))
}

// ── IO / hashing helpers ──────────────────────────────────────────────────────

/// Create the parent directory tree of `dest` (no-op if it already exists).
fn ensure_parent(dest: &Path) -> Result<()> {
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("cannot create directory '{}'", parent.display()))?;
    }
    Ok(())
}

/// Stream `reader` → `writer`, computing SHA-256 in a single pass.
/// Returns `(bytes_written, lowercase_hex_digest)`.
fn hash_and_copy<R: Read, W: Write>(reader: &mut R, writer: &mut W) -> Result<(u64, String)> {
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 65_536];
    let mut total: u64 = 0;

    loop {
        let n = reader.read(&mut buf).context("read error")?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        writer.write_all(&buf[..n]).context("write error")?;
        total += n as u64;
    }

    let hex = hex_string(&hasher.finalize());
    Ok((total, hex))
}

/// Compute SHA-256 of an existing file (used after `RawCollector` writes it).
fn sha256_of_file(path: &Path) -> Result<String> {
    let mut f = File::open(path)
        .with_context(|| format!("cannot open '{}' for hashing", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 65_536];

    loop {
        let n = f.read(&mut buf).context("hash read error")?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }

    Ok(hex_string(&hasher.finalize()))
}

/// Format a byte slice as a lowercase hexadecimal string.
fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
        s.push_str(&format!("{:02x}", b));
        s
    })
}

// ── Error classification ──────────────────────────────────────────────────────

/// True when `e` contains a Windows access-denied or sharing-violation error.
///
/// These are the conditions under which we attempt the NTFS raw-read fallback.
fn is_access_error(e: &anyhow::Error) -> bool {
    e.chain().any(|cause| {
        if let Some(io) = cause.downcast_ref::<std::io::Error>() {
            matches!(io.kind(), std::io::ErrorKind::PermissionDenied)
                || io.raw_os_error() == Some(32) // ERROR_SHARING_VIOLATION
        } else {
            false
        }
    })
}

/// True when `e` represents a "file not found" condition.
fn is_not_found_error(e: &anyhow::Error) -> bool {
    e.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .map(|io| io.kind() == std::io::ErrorKind::NotFound)
            .unwrap_or(false)
    })
}

/// Convert an `anyhow::Error` into a failed/skipped `CollectionResult`.
fn into_failed_result(
    source: &Path,
    dest: &Path,
    method: CollectionMethod,
    e: anyhow::Error,
) -> CollectionResult {
    let status = if is_not_found_error(&e) {
        CollectionStatus::Skipped(format!("file not found: {}", source.display()))
    } else {
        CollectionStatus::Failed(format!("{:#}", e))
    };

    CollectionResult {
        source_path: source.to_owned(),
        dest_path: dest.to_owned(),
        bytes_copied: 0,
        sha256: String::new(),
        method_used: method,
        fell_back: false,
        status,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_dest_strips_drive_letter() {
        let base = Path::new("output/HOST");
        let src = Path::new(r"C:\Windows\System32\config\SAM");
        let dest = build_dest_path(base, "Registry", src);
        assert_eq!(
            dest,
            PathBuf::from("output/HOST/Registry/Windows/System32/config/SAM")
        );
    }

    #[test]
    fn extract_volume_parses_c_drive() {
        let (vol, rel) = extract_volume(Path::new(r"C:\Windows\System32\config\SAM")).unwrap();
        assert_eq!(vol, "\\\\.\\C:");
        assert_eq!(rel, PathBuf::from(r"Windows\System32\config\SAM"));
    }

    #[test]
    fn extract_volume_requires_drive_letter() {
        assert!(extract_volume(Path::new(r"relative\path")).is_err());
    }

    #[test]
    fn hash_and_copy_round_trip() {
        let data = b"hello forensics";
        let mut src = std::io::Cursor::new(data);
        let mut dst = Vec::new();
        let (bytes, hex) = hash_and_copy(&mut src, &mut dst).unwrap();

        assert_eq!(bytes, data.len() as u64);
        assert_eq!(dst, data);
        assert_eq!(hex.len(), 64); // SHA-256 = 32 bytes = 64 hex chars
    }

    #[test]
    fn hex_string_correctness() {
        assert_eq!(hex_string(&[0x0a, 0xff, 0x00]), "0aff00");
    }
}
