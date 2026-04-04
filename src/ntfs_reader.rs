/// NTFS Raw-Read module.
///
/// Opens a Windows volume (e.g. `\\.\C:`) as **read-only** and uses the
/// `ntfs` crate to walk the MFT directly, bypassing any OS file locks that
/// would prevent normal `std::fs` access to in-use files such as the registry
/// hives or the Security event log.
use anyhow::{bail, Context, Result};
use ntfs::indexes::NtfsFileNameIndex;
use ntfs::{Ntfs, NtfsFile, NtfsReadSeek};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path};

// ── Sector-aligned volume reader ──────────────────────────────────────────────
//
// Windows raw volume handles (\\.\C:) impose two constraints:
//
//   1. ReadFile calls must use a buffer size that is a multiple of the
//      physical sector size (typically 512 bytes).
//
//   2. SetFilePointerEx with FILE_END is unsupported for volume handles.
//      The `ntfs` crate calls seek(SeekFrom::End(0)) inside Ntfs::new().
//
// SectorAlignedReader fixes both:
//   - Read-ahead buffer of CHUNK_SECTORS (1 MiB) so every underlying ReadFile
//     call transfers a full aligned chunk instead of one 512-byte sector.
//     This reduces syscall count by up to 2048× for large sequential files.
//   - SeekFrom::End is translated using the volume size from DeviceIoControl.

const SECTOR_SIZE: u64 = 512;
/// Number of sectors per read-ahead chunk (1 MiB).
const CHUNK_SECTORS: u64 = 2048;

struct SectorAlignedReader {
    inner: File,
    /// Total volume size in bytes (from IOCTL at open time).
    total_size: u64,
    /// Current logical read position.
    pos: u64,
    /// Read-ahead buffer: holds CHUNK_SECTORS * SECTOR_SIZE bytes.
    buf: Box<[u8]>,
    /// Sector index of the first sector in `buf` (u64::MAX = empty).
    buffered_start: u64,
    /// Number of valid sectors currently in `buf`.
    buffered_count: u64,
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

        let chunk_bytes = (CHUNK_SECTORS * SECTOR_SIZE) as usize;

        Ok(Self {
            inner,
            total_size,
            pos: 0,
            buf: vec![0u8; chunk_bytes].into_boxed_slice(),
            buffered_start: u64::MAX,
            buffered_count: 0,
        })
    }

    /// Ensure that the chunk containing `sector_idx` is loaded into `self.buf`.
    ///
    /// On a cache miss, aligns to the nearest CHUNK_SECTORS boundary and reads
    /// up to CHUNK_SECTORS sectors in a single ReadFile call, reducing syscall
    /// overhead for large sequential files by up to CHUNK_SECTORS (2048×).
    fn ensure_chunk(&mut self, sector_idx: u64) -> io::Result<()> {
        // Cache hit — sector is already in the buffer.
        if self.buffered_start != u64::MAX
            && sector_idx >= self.buffered_start
            && sector_idx < self.buffered_start + self.buffered_count
        {
            return Ok(());
        }

        // Align read start to a CHUNK_SECTORS boundary.
        let chunk_start = (sector_idx / CHUNK_SECTORS) * CHUNK_SECTORS;
        let offset = chunk_start * SECTOR_SIZE;

        // How many whole sectors remain from chunk_start to end of volume?
        let vol_sectors = self.total_size / SECTOR_SIZE;
        let available = vol_sectors.saturating_sub(chunk_start);
        let sectors_to_read = available.min(CHUNK_SECTORS) as usize;
        let bytes_to_read = sectors_to_read * SECTOR_SIZE as usize;

        self.inner.seek(SeekFrom::Start(offset))?;
        self.inner.read_exact(&mut self.buf[..bytes_to_read])?;

        self.buffered_start = chunk_start;
        self.buffered_count = sectors_to_read as u64;
        Ok(())
    }
}

impl Read for SectorAlignedReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.pos >= self.total_size {
            return Ok(0);
        }

        let sector_idx = self.pos / SECTOR_SIZE;
        self.ensure_chunk(sector_idx)?;

        // Serve as many bytes as possible from the buffered chunk.
        let buf_start = self.buffered_start * SECTOR_SIZE;
        let buf_offset = (self.pos - buf_start) as usize;
        let buffered_bytes = (self.buffered_count * SECTOR_SIZE) as usize;
        let from_buf = buffered_bytes - buf_offset;
        let from_vol = (self.total_size - self.pos) as usize;
        let available = from_buf.min(from_vol);
        let to_copy = buf.len().min(available);

        buf[..to_copy].copy_from_slice(&self.buf[buf_offset..buf_offset + to_copy]);
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
            // Translate it using the size obtained at open time.
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
    /// `Windows\System32\config\SAM`.
    ///
    /// `stream` selects the named `$DATA` attribute to extract.
    /// Pass `None` (or `Some("")`) for the unnamed default stream.
    ///
    /// Returns `(bytes_written, sha256_hex)`. The SHA-256 is computed in a
    /// single pass during the write — no second read of the output file.
    pub fn extract_file(
        &mut self,
        ntfs_path: &Path,
        stream: Option<&str>,
        dest: &Path,
    ) -> Result<(u64, String)> {
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

        let stream_name = stream.unwrap_or("");
        let (bytes, sha256) =
            copy_data(&self.ntfs, &mut self.source, &file, stream_name, &mut writer)
                .with_context(|| {
                    if stream_name.is_empty() {
                        format!("error extracting '{}'", ntfs_path.display())
                    } else {
                        format!(
                            "error extracting '{}' (stream: {})",
                            ntfs_path.display(),
                            stream_name
                        )
                    }
                })?;

        writer.flush().context("flush error")?;
        Ok((bytes, sha256))
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Walk the directory tree component-by-component and return the target
/// [`NtfsFile`].
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

/// Copy the named `$DATA` stream of `file` into `writer`, computing SHA-256
/// in the same pass.
///
/// Returns `(bytes_written, sha256_hex)`.
fn copy_data<'n, T, W>(
    _ntfs: &'n Ntfs,
    source: &mut T,
    file: &NtfsFile<'n>,
    stream_name: &str,
    writer: &mut W,
) -> Result<(u64, String)>
where
    T: Read + Seek,
    W: Write,
{
    let data_item = file
        .data(source, stream_name)
        .ok_or_else(|| {
            if stream_name.is_empty() {
                anyhow::anyhow!("file has no $DATA attribute (sparse or directory?)")
            } else {
                anyhow::anyhow!("file has no '{}' alternate data stream", stream_name)
            }
        })?
        .context("error accessing $DATA attribute")?;

    let data_attribute = data_item
        .to_attribute()
        .context("failed to get $DATA attribute")?;

    let mut data_value = data_attribute
        .value(source)
        .context("failed to get $DATA value")?;

    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 65_536];
    let mut total: u64 = 0;

    loop {
        let n = data_value
            .read(source, &mut buf)
            .context("error reading file data from volume")?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        writer.write_all(&buf[..n]).context("write error")?;
        total += n as u64;
    }

    Ok((total, hex_string(&hasher.finalize())))
}

/// Extract meaningful path components, dropping drive-letter prefix and root.
fn path_components(path: &Path) -> Vec<String> {
    path.components()
        .filter_map(|c| match c {
            Component::Normal(s) => s.to_str().map(str::to_owned),
            _ => None,
        })
        .collect()
}

fn hex_string(bytes: &[u8]) -> String {
    use std::fmt::Write as FmtWrite;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(s, "{b:02x}").unwrap();
    }
    s
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
