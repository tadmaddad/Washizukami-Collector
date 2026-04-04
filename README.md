<div align="center">
 <p>
    <img alt="Washizukami Logo" src="Logo.png" width="60%">
 </p>
 [ <b>English</b> ] | [<a href="README-Japanese.md">日本語</a>]
</div>

---

# Washizukami (鷲掴)

> **Windows Forensic Evidence Collection Tool**

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)
[![Built with Rust](https://img.shields.io/badge/Built%20with-Rust-orange.svg)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11%20x64-blue.svg)]()

---

## Overview

**Washizukami (鷲掴)** is a fast forensic evidence collection tool for Windows, implemented in Rust.

Even when the OS has files locked, it can acquire artifacts such as registry hives and event logs by directly parsing the NTFS Master File Table (MFT). Collected evidence is saved alongside an audit log containing SHA-256 hashes, making it ready to feed directly into various analysis tools.

This tool was inspired by [CDIR-C](https://github.com/CyberDefenseInstitute/CDIR) (Cyber Defense Institute). It aims to deliver the live-system artifact collection approach pioneered by CDIR-C as a portable single binary through a Rust implementation.

**Example analysis tools it pairs with:**
- [Hayabusa](https://github.com/Yamato-Security/hayabusa) — Threat hunting for Windows event logs
- [Velociraptor](https://github.com/Velocidex/velociraptor) / [KAPE](https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape) and other forensic frameworks
- Ingestion into SIEMs such as ELK Stack / Splunk

---

## Features

| Feature | Description |
|---------|-------------|
| **NTFS Raw Read** | Directly parses the MFT to bypass OS file locks during collection |
| **SHA-256 Integrity Verification** | Hashes all collected files to enable tamper detection |
| **Audit Log** | Structured log (`collection.log`) containing timestamps, collection method, and SHA-256 hashes |
| **Single Binary** | Artifact definitions are embedded at compile time — no external files needed at runtime |
| **Flexible Filtering** | Filter by category via `--category` (include or exclude with `!` prefix), or fine-tune via `config.yaml` |
| **ZIP Output** | Compresses all collected artifacts into a single ZIP after collection for easy exfiltration |
| **Memory Acquisition Integration** | `--mem` option integrates with [WinPmem](https://github.com/Velocidex/WinPmem) to capture memory dumps |
| **Dry-Run Mode** | Verify collection target paths without touching the filesystem |
| **YARA Scanning** | `scan` subcommand scans persistence mechanisms with YARA-X, collecting detected files into `infected.zip` |
| **Confirmation Prompt** | Prompts `[y/N]` before starting collection or scanning to prevent accidental execution |

---

## Requirements

| Item | Requirement |
|------|-------------|
| **OS** | Windows 10 / Windows 11 (x64) |
| **Privileges** | Must be run with **Administrator** privileges |
| **Runtime** | Not required (statically built — no VC++ Redistributable or MinGW DLLs needed) |
| **Disk Space** | At least equal to the total size of artifacts to be collected |
| **Memory Acquisition Option** | When using `--mem`, place `winpmem*.exe` in the `tools\` folder |

> **Note:** Because NTFS Raw Read is used, the target volume must be NTFS-formatted. Files on FAT32/exFAT volumes are collected using the standard File collector.

---

## Usage

### Artifact Collection Mode (Default)

```
washi.exe [OPTIONS]

Options:
  -o, --output <DIR>               Output directory
                                   [Default: <executable folder>\output\<COMPUTERNAME>]
  -c, --category <CATEGORY>        Filter by category (repeatable, case-insensitive).
                                   Without prefix: collect only these categories.
                                   With '!' prefix: exclude these categories.
                                   Available: EventLogs, Registry, NTFS, Filesystem, WMI, SRUM, Web
      --dry-run                    Display path resolution results only (no files are collected)
      --zip                        Generate a ZIP archive after collection
      --mem                        Capture memory dump with tools\winpmem*.exe (runs before collection)
      --volume <LETTER>            Override the drive letter for NTFS Raw Read
  -v, --verbose                    Show every collected file instead of one summary line per category
  -h, --help
  -V, --version
```

### YARA Scan Mode

```
washi.exe scan [OPTIONS] --rules <FILE> --output <DIR>

Options:
      --yara-path <PATH>           Path to YARA-X engine (yr.exe) [Default: ./tools/yr.exe]
      --rules <FILE>               Path to YARA rules file (required)
      --output <DIR>               Output directory for scan results (required)
  -h, --help
```

Scan targets are automatically collected from the following persistence mechanisms:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `C:\Windows\System32\Tasks` (Task Scheduler XML)

### Confirmation Prompt

Before starting collection or a YARA scan, washi.exe displays a confirmation prompt:

```
[?] Start collection? [y/N]:
```

Type `y` or `yes` (case-insensitive) to proceed. Any other input, pressing Enter alone, or Ctrl+C will abort. `--dry-run` skips the prompt since no files are written.

### Examples

```powershell
# Collect all artifacts (with audit log)
washi.exe

# Generate a ZIP archive after collection
washi.exe --zip

# Capture memory dump → Collect all artifacts → Generate ZIP
washi.exe --mem --zip

# Collect Registry and EventLogs only
washi.exe --category Registry --category EventLogs

# Collect everything except EventLogs and WMI
washi.exe --category '!EventLogs' --category '!WMI'

# Show every collected file (verbose output)
washi.exe --verbose

# Verify collection targets (no files are written)
washi.exe --dry-run

# Specify output directory
washi.exe --output D:\evidence\case001 --zip

# YARA scan (scan persistence paths and collect detected files into infected.zip)
washi.exe scan --rules C:\rules\malware.yar --output C:\scan_out
```

---

## Collected Artifacts

Below is the list of artifacts covered by the built-in definitions. You can also add custom definitions via `config.yaml` (see "Customizing Artifact Definitions" for details).

| Category | Artifact | Collection Method |
|----------|----------|-------------------|
| **EventLogs** | Security / System / Application Event Log | NTFS |
| **Registry** | SAM / SECURITY / SOFTWARE / SYSTEM hives | NTFS |
| **Registry** | Amcache.hve | NTFS |
| **Registry** | NTUSER.DAT / UsrClass.dat (all users) | NTFS |
| **NTFS** | `$MFT` (Master File Table) | NTFS |
| **NTFS** | `$SECURE:$SDS` (Security Descriptor Stream) | NTFS + ADS |
| **NTFS** | `$UsnJrnl:$J` (USN Journal) | NTFS + ADS |
| **Filesystem** | Prefetch files (`Prefetch\*.pf`) | File |
| **Filesystem** | Recent files (`Recent\*.lnk`) | File |
| **WMI** | WMI Repository (OBJECTS.DATA / INDEX.BTR / MAPPING*.MAP) | NTFS |
| **SRUM** | SRUM Database (SRUDB.dat) | NTFS |
| **Web** | Chrome History | File |
| **Web** | Firefox History & Cookies (places.sqlite / cookies.sqlite) | File |
| **Web** | IE / Edge WebCache (WebCacheV01.dat) | File |
| **Web** | Edge History | File |

> **NTFS + ADS:** Alternate Data Streams are acquired via direct MFT reads. This enables access to streams that cannot be read through normal APIs.

---

## Output Structure

```
<executable folder>\
├── output\
│   └── HOSTNAME\
│       ├── collection.log      ← Audit log (timestamps, SHA-256, collection method)
│       ├── memory.dmp          ← Memory dump (only when --mem is specified)
│       ├── EventLogs\
│       │   ├── Security.evtx
│       │   └── ...
│       ├── Registry\
│       │   ├── SAM
│       │   └── ...
│       ├── NTFS\
│       │   ├── $MFT
│       │   ├── $Secure_SDS     ← $SECURE:$SDS stream
│       │   └── $UsnJrnl_J      ← $UsnJrnl:$J stream
│       ├── Filesystem\
│       │   └── ...
│       ├── WMI\
│       │   └── ...
│       ├── SRUM\
│       │   └── SRUDB.dat
│       └── Web\
│           └── ...
└── output\HOSTNAME.zip         ← ZIP archive (only when --zip is specified)
```

### Audit Log Format

```
[2026-03-21T10:30:00+0900] [OK   ] [NTFS        ] C:\Windows\System32\config\SAM -> output\HOSTNAME\Registry\SAM (262144 bytes, SHA256: abcd1234...)
[2026-03-21T10:30:01+0900] [SKIP ] [-           ] C:\path\missing — file not found
[2026-03-21T10:30:02+0900] [FAIL ] [-           ] C:\path\locked — <error>
[2026-03-21T10:30:03+0900] [TOOL ] [winpmem_x64 ] Starting: tools\winpmem_x64.exe -> output\HOSTNAME\memory.dmp
[2026-03-21T10:30:10+0900] [INFO ] [-           ] Complete — OK: 141  Skipped: 1  Failed: 0

# When running washi.exe scan
[2026-03-23T11:00:00+0900] [SCAN ] [yr          ] Starting scan — engine: ./tools/yr.exe  rules: malware.yar  targets: 59
[2026-03-23T11:00:02+0900] [MATCH] [yara        ] C:\Windows\System32\notepad.exe — test_notepad
[2026-03-23T11:00:02+0900] [SCAN ] [-           ] Complete — matched: 1  archive: scan_out\infected.zip
```

---

## Customizing Artifact Definitions

The built-in definitions cover Windows event logs, registry hives, and common filesystem artifacts. By placing a `config.yaml` in the same folder as `washi.exe`, you can narrow collection targets or add custom artifacts.

**Priority:** CLI flags > `config.yaml` > built-in defaults

### Filters

#### `enabled_artifacts`

Whitelist of artifact names to collect. If empty or omitted, all artifacts are collected. Matching is case-insensitive.

<details>
<summary>Built-in artifact names</summary>

| Category | Name |
|----------|------|
| EventLogs | `Security Event Log` |
| EventLogs | `System Event Log` |
| EventLogs | `Application Event Log` |
| Registry | `SAM Registry Hive` |
| Registry | `SECURITY Registry Hive` |
| Registry | `SOFTWARE Registry Hive` |
| Registry | `SYSTEM Registry Hive` |
| Registry | `Amcache.hve` |
| Registry | `User NTUSER.DAT` |
| Registry | `User UsrClass.dat` |
| NTFS | `$MFT` |
| NTFS | `$SECURE:$SDS` |
| NTFS | `$UsnJrnl:$J` |
| Filesystem | `Prefetch Files` |
| Filesystem | `Recent LNK Files` |
| WMI | `WMI Repository OBJECTS.DATA` |
| WMI | `WMI Repository INDEX.BTR` |
| WMI | `WMI Repository MAPPING Files` |
| SRUM | `SRUM Database` |
| Web | `Chrome History` |
| Web | `Firefox places.sqlite` |
| Web | `Firefox cookies.sqlite` |
| Web | `IE/Edge WebCacheV01.dat` |
| Web | `Edge History` |

</details>

#### `disabled_categories`

Excludes entire categories from collection. Valid values: `EventLogs` / `Registry` / `NTFS` / `Filesystem` / `WMI` / `SRUM` / `Web` (case-insensitive).

> **Note:** `disabled_categories` is evaluated **after** `enabled_artifacts`. An artifact explicitly listed in `enabled_artifacts` will still be excluded if its category appears in `disabled_categories`.

### Custom Artifact Definitions

Use the `artifacts` key to add artifacts not covered by the built-in definitions. If a custom entry shares the same `name` as a built-in artifact, the custom definition takes priority.

Required fields:

| Field | Description |
|-------|-------------|
| `name` | Unique display name. Referenced by `enabled_artifacts` in `config.yaml`. |
| `category` | Group name. Also used as the output subfolder name. |
| `target_path` | Path to collect. Supports `%VAR%` environment variables and glob wildcards (`*` and `?`). |
| `method` | `File` — standard OS copy. `NTFS` — direct MFT read, bypasses file locks. |

### Example `config.yaml`

```yaml
# ── Filters ──────────────────────────────────────────────────────────────────
# Collect only these artifacts (comment out to collect all)
enabled_artifacts:
  - "SAM Registry Hive"
  - "Security Event Log"
  - "System Event Log"

# Exclude entire categories
disabled_categories:
  - Filesystem
  - Web

# ── Custom artifact definitions ───────────────────────────────────────────────
artifacts:
  - name: "My Application Log"
    category: "Custom"
    target_path: "C:\\MyApp\\logs\\app.log"
    method: File

  - name: "My Locked DB"
    category: "Custom"
    target_path: "%SystemDrive%\\MyApp\\data\\app.db"
    method: NTFS

  - name: "All XML Configs"
    category: "Custom"
    target_path: "C:\\MyApp\\config\\*.xml"
    method: File
```

### Recipe: Collecting Outlook .pst Files

Classic Outlook (not the New Outlook app) stores `.pst` files in a location that varies by environment. On **Japanese Windows with OneDrive enabled**, the default path is:

```
C:\Users\<username>\OneDrive\ドキュメント\Outlook ファイル\*.pst
```

Add the following entry to `config.yaml` to collect `.pst` files across all user profiles:

```yaml
artifacts:
  - name: "Outlook PST Files"
    category: "Mail"
    target_path: "C:\\Users\\*\\OneDrive\\ドキュメント\\Outlook ファイル\\*.pst"
    method: NTFS
```

> **Why `method: NTFS`?** Classic Outlook holds an exclusive lock on `.pst` files while running. Using NTFS raw read bypasses the lock and allows collection without closing Outlook.
>
> **Size warning:** `.pst` files can be several GB. Run `--dry-run` first to check sizes before collecting.

---

## Memory Acquisition (WinPmem Integration)

Using the `--mem` option, you can capture a memory dump with [WinPmem](https://github.com/Velocidex/WinPmem) before artifact collection begins.

1. Download `winpmem_x64.exe` from the [WinPmem Releases page](https://github.com/Velocidex/WinPmem/releases)
2. Place it in the `tools\` folder alongside `washi.exe`
3. Run with the `--mem` flag

```
(Directory layout)
washi.exe
tools\
└── winpmem_x64.exe
```

> If `tools\winpmem*.exe` is not found, a warning is logged and artifact collection proceeds without memory acquisition.

---

## Building from Source

**Prerequisites:**
- Rust stable toolchain (`x86_64-pc-windows-gnu`)
- MSYS2 + MinGW-w64 (GNU linker)

```powershell
git clone https://github.com/tadmaddad/Washizukami-Collector.git
cd Washizukami-Collector
cargo build --release
```

---

## Roadmap

The following feature enhancements are currently planned or under consideration. Implementation order is undecided.

### YARA Scan Enhancements

The `scan` subcommand was implemented in v0.4.0. The following enhancements are being considered:

- `--target` option for scanning arbitrary directories
- Password protection for `infected.zip` (AES-256) — currently unimplemented due to build environment constraints
- Expanded scan targets (Startup folders, service registration paths, etc.)

### Email Client Artifacts

#### Microsoft Outlook `.pst` — available now via `config.yaml`

Classic Outlook `.pst` collection is already supported through custom artifact definitions. See the [Recipe: Collecting Outlook .pst Files](#recipe-collecting-outlook-pst-files) section for configuration details.

#### Planned built-in support

The following are planned as future built-in definitions:

| Client | Target Files |
|--------|-------------|
| **Microsoft Outlook** | `.ost` files, attachment cache |
| **Mozilla Thunderbird** | Mailboxes (`*.msf` / `INBOX`), address books, configuration files |

Since email data tends to be large, optimizations such as date-range filtering and differential collection are also being considered.

---

## Origin of the Name: Why "Washizukami (鷲掴)"?

This tool is named out of deep respect for **[Hayabusa](https://github.com/Yamato-Security/hayabusa)**, the de facto standard for Windows log analysis and a favorite among security engineers.

If the Hayabusa (Peregrine Falcon) — the king of the skies — spots its prey with razor-sharp eyes, then this tool physically "eagle-grabs" (鷲掴み) that prey (artifacts), overpowering even OS restrictions (file locks) to bring them back. The name embodies that commitment to powerful evidence collection.

...That said, the above is the official (serious) explanation.

We occasionally receive insinuations that "the author's personal preferences may be reflected in the naming," but this is categorically untrue. All we want is to hold NTFS MFT entries and registry hives — firmly, yet gently — through legally proper procedures.

---

## AI-Assisted Development

This project was developed with the assistance of two powerful AI assistants: **Claude Code** and **Google Gemini**.

- **Claude Code**: Primarily assisted with Rust code structure design, refactoring, and implementation guidance for Windows-specific system programming.
- **Google Gemini**: Assisted with overall project roadmap planning, documentation, and served as a sounding board for troubleshooting.

---

## License

Copyright (C) 2026 tadmaddad - Jawfish Lab

This software is released as open source under the GNU Affero General Public License v3.0 (AGPL-3.0).

---

## Libraries & Tools Used

- [ntfs](https://github.com/ColinFinck/ntfs) by Colin Finck — Pure Rust NTFS parser enabling direct MFT access
- [WinPmem](https://github.com/Velocidex/WinPmem) by Velocidex — Windows memory acquisition tool
