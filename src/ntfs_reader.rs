/// NTFS Raw-Read module.
///
/// Opens a Windows volume (e.g. `\\.\C:`) as **read-only** and uses the
/// `ntfs` crate to walk the MFT directly, bypassing any OS file locks that
/// would prevent normal `std::fs` access to in-use files such as the registry
/// hives or the Security event log.
use anyhow::{bail, Context, Result};
use ntfs::indexes::NtfsFileNameIndex;
use ntfs::{Ntfs, NtfsFile, NtfsReadSeek};
use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path};

// ── Sector-aligned volume reader ──────────────────────────────────────────────
//
// Windows raw volume handles (\\.\C:) impose two constraints that plain
// std::fs::File does not satisfy on its own:
//
//   1. ReadFile calls must use a buffer size that is a multiple of the
//      physical sector size (typically 512 bytes).  Reads of e.g. 3 bytes
//      (such as the NTFS "bootjmp" field) fail with ERROR_INVALID_PARAMETER.
//
//   2. SetFilePointerEx with FILE_END is unsupported for volume handles and
//      also returns ERROR_INVALID_PARAMETER.  The `ntfs` crate calls
//      seek(SeekFrom::End(0)) inside Ntfs::new() to determine total size.
//
// SectorAlignedReader fixes both by:
//   - Caching one sector (512 bytes) and serving Read requests from it,
//     so every underlying ReadFile call is 512-byte aligned in size and offset.
//   - Implementing SeekFrom::End using the volume size obtained once at open
//     time via DeviceIoControl(IOCTL_DISK_GET_LENGTH_INFO).

const SECTOR_SIZE: u64 = 512;

struct SectorAlignedReader {
    inner: File,
    /// Total volume size in bytes (from IOCTL at open time).
    total_size: u64,
    /// Current logical read position.
    pos: u64,
    /// One-sector read buffer.
    buf: Box<[u8; SECTOR_SIZE as usize]>,
    /// Which sector number is currently in `buf` (u64::MAX = invalid/empty).
    buffered_sector: u64,
}

impl SectorAlignedReader {
    fn open(path: &str) -> Result<Self> {
        let inner = OpenOptions::new()
            .read(true)
            .write(false)
            .open(path)
            .with_context(|| {
                format!("cannot open volume '{path}' – is this process running as Administrator?")
            })?;

        let total_size = query_volume_size(&inner)
            .with_context(|| format!("cannot determine size of volume '{path}'"))?;

        Ok(Self {
            inner,
            total_size,
            pos: 0,
            buf: Box::new([0u8; SECTOR_SIZE as usize]),
            buffered_sector: u64::MAX,
        })
    }

    /// Load sector `idx` into `self.buf` if it is not already cached.
    fn ensure_sector(&mut self, idx: u64) -> io::Result<()> {
        if self.buffered_sector == idx {
            return Ok(());
        }
        let offset = idx * SECTOR_SIZE;
        // Seek the inner file directly — this is always sector-aligned.
        self.inner.seek(SeekFrom::Start(offset))?;
        self.inner.read_exact(self.buf.as_mut())?;
        self.buffered_sector = idx;
        Ok(())
    }
}

impl Read for SectorAlignedReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.pos >= self.total_size {
            return Ok(0);
        }
        let sector_idx = self.pos / SECTOR_SIZE;
        let sector_off = (self.pos % SECTOR_SIZE) as usize;

        self.ensure_sector(sector_idx)?;

        let available = SECTOR_SIZE as usize - sector_off;
        let to_copy = buf.len().min(available);
        buf[..to_copy].copy_from_slice(&self.buf[sector_off..sector_off + to_copy]);
        self.pos += to_copy as u64;
        Ok(to_copy)
    }
}

impl Seek for SectorAlignedReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_pos: u64 = match pos {
            SeekFrom::Start(n) => n,
            SeekFrom::Current(n) => {
                let p = self.pos as i64 + n;
                if p < 0 {
                    return Err(io::Error::new(io::ErrorKind::InvalidInput, "seek before start"));
                }
                p as u64
            }
            // SeekFrom::End is unsupported by Windows volume handles.
            // Translate it using the size we obtained at open time.
            SeekFrom::End(n) => {
                let p = self.total_size as i64 + n;
                if p < 0 {
                    return Err(io::Error::new(io::ErrorKind::InvalidInput, "seek before start"));
                }
                p as u64
            }
        };
        self.pos = new_pos;
        Ok(new_pos)
    }
}

/// Query the total byte size of a Windows volume handle using
/// `DeviceIoControl(IOCTL_DISK_GET_LENGTH_INFO)`.
#[cfg(windows)]
fn query_volume_size(file: &File) -> Result<u64> {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::IO::DeviceIoControl;

    // CTL_CODE(IOCTL_DISK_BASE=7, 0x17, METHOD_BUFFERED=0, FILE_READ_ACCESS=1) = 0x0007_405C
    const IOCTL_DISK_GET_LENGTH_INFO: u32 = 0x0007_405C;

    #[repr(C)]
    struct GetLengthInformation {
        length: i64,
    }

    let handle = HANDLE(file.as_raw_handle());
    let mut info = GetLengthInformation { length: 0 };
    let mut returned: u32 = 0;

    unsafe {
        DeviceIoControl(
            handle,
            IOCTL_DISK_GET_LENGTH_INFO,
            None,
            0,
            Some(&mut info as *mut _ as *mut _),
            std::mem::size_of::<GetLengthInformation>() as u32,
            Some(&mut returned),
            None,
        )
        .context("DeviceIoControl(IOCTL_DISK_GET_LENGTH_INFO) failed")?;
    }

    Ok(info.length as u64)
}

/// Fallback for non-Windows: use a regular seek-to-end.
#[cfg(not(windows))]
fn query_volume_size(file: &File) -> Result<u64> {
    let mut f = file.try_clone().context("cannot clone file handle")?;
    f.seek(SeekFrom::End(0)).context("seek to end failed")
}

// ── Public API ────────────────────────────────────────────────────────────────

/// A handle to a mounted NTFS volume opened for raw, read-only access.
pub struct NtfsReader {
    source: SectorAlignedReader,
    /// Parsed NTFS metadata (boot sector + upcase table).
    ntfs: Ntfs,
}

impl NtfsReader {
    /// Open `volume` (e.g. `"\\.\C:"`) read-only and initialise the NTFS parser.
    ///
    /// Requires Administrator privileges; the caller should invoke
    /// [`crate::privileges::require_elevation`] before calling this.
    pub fn open(volume: &str) -> Result<Self> {
        let mut source = SectorAlignedReader::open(volume)?;

        let mut ntfs = Ntfs::new(&mut source)
            .with_context(|| format!("failed to parse NTFS on '{volume}'"))?;

        // Load the upcase table so that directory lookups are case-insensitive
        // (matching NTFS behaviour on Windows).
        ntfs.read_upcase_table(&mut source)
            .context("failed to read NTFS upcase table")?;

        Ok(Self { source, ntfs })
    }

    /// Extract a single locked/in-use file at `ntfs_path` to `dest`.
    ///
    /// `ntfs_path` is a path **relative to the volume root**, e.g.
    /// `Windows\System32\config\SAM`.  Both `\` and `/` separators are
    /// accepted.  Drive-letter prefixes such as `C:\` are stripped
    /// automatically.
    ///
    /// Returns the number of bytes written to `dest`.
    pub fn extract_file(&mut self, ntfs_path: &Path, dest: &Path) -> Result<u64> {
        let components = path_components(ntfs_path);
        if components.is_empty() {
            bail!("ntfs_path is empty: {}", ntfs_path.display());
        }

        let file = traverse(&self.ntfs, &mut self.source, &components)?;

        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("cannot create output directory '{}'", parent.display()))?;
        }

        let out = File::create(dest)
            .with_context(|| format!("cannot create output file '{}'", dest.display()))?;
        let mut writer = BufWriter::new(out);

        let bytes = copy_data(&self.ntfs, &mut self.source, &file, &mut writer)
            .with_context(|| format!("error extracting '{}'", ntfs_path.display()))?;

        Ok(bytes)
    }

    /// Read a locked/in-use file at `ntfs_path` fully into memory.
    ///
    /// Use [`extract_file`] for large files to avoid excessive memory usage.
    pub fn read_to_vec(&mut self, ntfs_path: &Path) -> Result<Vec<u8>> {
        let components = path_components(ntfs_path);
        if components.is_empty() {
            bail!("ntfs_path is empty: {}", ntfs_path.display());
        }

        let file = traverse(&self.ntfs, &mut self.source, &components)?;

        let mut buf = Vec::new();
        copy_data(&self.ntfs, &mut self.source, &file, &mut buf)
            .with_context(|| format!("error reading '{}'", ntfs_path.display()))?;

        Ok(buf)
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Walk the directory tree component-by-component and return the target
/// [`NtfsFile`].
///
/// Uses [`NtfsFileNameIndex::find`] for each level, which performs an O(log n)
/// B-tree search using the NTFS upcase table for case-insensitive matching.
fn traverse<'n, T>(
    ntfs: &'n Ntfs,
    source: &mut T,
    components: &[String],
) -> Result<NtfsFile<'n>>
where
    T: Read + Seek,
{
    let mut current: NtfsFile<'n> = ntfs
        .root_directory(source)
        .context("failed to open NTFS root directory")?;

    for component in components {
        // Each iteration is in its own block so that `index`, `finder`, and
        // `entry` — which borrow from `current` — are dropped before
        // `current` is overwritten.
        let next: NtfsFile<'n> = {
            let index = current
                .directory_index(source)
                .with_context(|| format!("'{}' is not a directory", component))?;

            let mut finder = index.finder();

            let entry = NtfsFileNameIndex::find(&mut finder, ntfs, source, component)
                .ok_or_else(|| anyhow::anyhow!("'{}' not found", component))?
                .with_context(|| format!("error searching for '{}'", component))?;

            entry
                .to_file(ntfs, source)
                .with_context(|| format!("failed to open '{}' from MFT", component))?
        };

        current = next;
    }

    Ok(current)
}

/// Copy the unnamed `$DATA` stream of `file` into `writer` using a 64 KiB
/// streaming buffer.  Returns the number of bytes written.
///
/// Reading via the raw volume handle means Windows file locks on `file` are
/// completely bypassed.
fn copy_data<'n, T, W>(
    _ntfs: &'n Ntfs,
    source: &mut T,
    file: &NtfsFile<'n>,
    writer: &mut W,
) -> Result<u64>
where
    T: Read + Seek,
    W: Write,
{
    let data_item = file
        .data(source, "")
        .ok_or_else(|| anyhow::anyhow!("file has no $DATA attribute (sparse or directory?)"))?
        .context("error accessing $DATA attribute")?;

    let data_attribute = data_item
        .to_attribute()
        .context("failed to get $DATA attribute")?;

    let mut data_value = data_attribute
        .value(source)
        .context("failed to get $DATA value")?;

    let mut buf = vec![0u8; 65_536];
    let mut total: u64 = 0;

    loop {
        let n = data_value
            .read(source, &mut buf)
            .context("error reading file data from volume")?;
        if n == 0 {
            break;
        }
        writer.write_all(&buf[..n]).context("write error")?;
        total += n as u64;
    }

    Ok(total)
}

/// Extract the meaningful path components from a Windows path, dropping any
/// drive-letter prefix (e.g. `C:\`) and root separator.
///
/// `Windows\System32\config\SAM` → `["Windows", "System32", "config", "SAM"]`
/// `C:\Windows\System32\config\SAM` → same result
fn path_components(path: &Path) -> Vec<String> {
    path.components()
        .filter_map(|c| match c {
            Component::Normal(s) => s.to_str().map(str::to_owned),
            _ => None,
        })
        .collect()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_components_strips_drive_letter() {
        let p = Path::new(r"C:\Windows\System32\config\SAM");
        assert_eq!(
            path_components(p),
            ["Windows", "System32", "config", "SAM"]
        );
    }

    #[test]
    fn path_components_relative() {
        let p = Path::new(r"Windows\System32\config\SAM");
        assert_eq!(
            path_components(p),
            ["Windows", "System32", "config", "SAM"]
        );
    }

    #[test]
    fn path_components_single() {
        let p = Path::new(r"pagefile.sys");
        assert_eq!(path_components(p), ["pagefile.sys"]);
    }
}
