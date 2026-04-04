//! Artifact definition management.
//!
//! Standard definitions are **embedded in the binary** at compile time via
//! `include_str!`, so the tool works as a single executable without needing
//! the `artifacts/` directory at runtime.
//!
//! An optional `config.yaml` placed beside the executable lets operators
//! add custom artifact definitions and/or filter which artifacts are
//! collected without rebuilding the binary.
//!
//! Resolution order (highest priority first):
//!   1. CLI `CollectionFilter` (passed as `Some(&filter)`)
//!   2. `<exe_dir>/config.yaml`
//!   3. Embedded defaults (all artifacts collected)
//!
//! Custom artifacts defined in `config.yaml` are merged with the embedded
//! definitions before filtering.  If a custom entry shares a `name` with an
//! embedded entry the custom definition takes precedence.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

// ── Embedded YAML sources ─────────────────────────────────────────────────────

const EMBEDDED_EVENTLOGS: &str = include_str!("../artifacts/windows_eventlogs.yaml");
const EMBEDDED_REGISTRY: &str = include_str!("../artifacts/windows_registry.yaml");
const EMBEDDED_NTFS: &str = include_str!("../artifacts/windows_ntfs.yaml");
const EMBEDDED_FILESYSTEM: &str = include_str!("../artifacts/windows_filesystem.yaml");
const EMBEDDED_WMI: &str = include_str!("../artifacts/windows_wmi.yaml");
const EMBEDDED_SRUM: &str = include_str!("../artifacts/windows_srum.yaml");
const EMBEDDED_WEB: &str = include_str!("../artifacts/windows_web.yaml");

/// All embedded artifact YAML sources, in load order.
static EMBEDDED_SOURCES: &[(&str, &str)] = &[
    ("windows_eventlogs.yaml", EMBEDDED_EVENTLOGS),
    ("windows_registry.yaml", EMBEDDED_REGISTRY),
    ("windows_ntfs.yaml", EMBEDDED_NTFS),
    ("windows_filesystem.yaml", EMBEDDED_FILESYSTEM),
    ("windows_wmi.yaml", EMBEDDED_WMI),
    ("windows_srum.yaml", EMBEDDED_SRUM),
    ("windows_web.yaml", EMBEDDED_WEB),
];

// ── Core types ────────────────────────────────────────────────────────────────

/// How an artifact is read off disk.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CollectionMethod {
    /// Raw NTFS / MFT traversal — bypasses OS file locks.
    NTFS,
    /// Standard OS file-system copy (`std::fs`).
    File,
}

/// A single artifact entry as defined in the YAML source files.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactDefinition {
    /// Human-readable name, e.g. `"Security Event Log"`.
    pub name: String,
    /// Grouping category, e.g. `"EventLogs"` or `"Registry"`.
    pub category: String,
    /// Target path — may contain `%VAR%` and glob wildcards.
    pub target_path: String,
    /// Collection method to use for this artifact.
    pub method: CollectionMethod,
    /// Optional NTFS Alternate Data Stream name (e.g. `"$SDS"`, `"$J"`).
    /// When set, the named stream is read instead of the unnamed `$DATA` stream.
    /// Only meaningful when `method` is `NTFS`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream: Option<String>,
}

// ── Filter type ───────────────────────────────────────────────────────────────

/// Criteria for selecting which artifacts to collect.
///
/// Used both by the external `config.yaml` and by CLI flags.
///
/// ### Filtering rules (applied in order)
///
/// 1. **Category whitelist** (`enabled_categories`): if non-empty, only
///    artifacts whose `category` appears in this list are kept.
///    Case-insensitive.  Set by CLI `--category Foo` (no prefix).
/// 2. **Artifact whitelist** (`enabled_artifacts`): if non-empty, only
///    artifacts whose `name` appears in this list are kept.
///    Case-insensitive.  Available via `config.yaml` only.
/// 3. **Category blacklist** (`disabled_categories`): artifacts whose
///    `category` appears in this list are removed.  Case-insensitive.
///    Set by CLI `--category !Foo` or `config.yaml`.
///
/// An empty filter (all lists empty) is a no-op — all artifacts are kept.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CollectionFilter {
    /// Category whitelist.  Empty = no restriction.
    /// CLI source: `--category Foo` (no `!` prefix).
    #[serde(default)]
    pub enabled_categories: Vec<String>,

    /// Artifact name whitelist.  Empty = no restriction.
    /// Available via `config.yaml` only (not exposed as a CLI flag).
    #[serde(default)]
    pub enabled_artifacts: Vec<String>,

    /// Category blacklist.  Empty = no restriction.
    /// CLI source: `--category !Foo`.
    #[serde(default)]
    pub disabled_categories: Vec<String>,
}

/// Full contents of an external `config.yaml` file.
///
/// Combines a [`CollectionFilter`] (which artifacts to include/exclude) with
/// an optional list of **custom artifact definitions** that extend or override
/// the embedded defaults.
///
/// ### `config.yaml` example
///
/// ```yaml
/// # ── フィルタ ──────────────────────────────────────────────────────────────
///
/// # このリストが空でない場合、ここに列挙した名前のアーティファクトのみ収集
/// enabled_artifacts:
///   - SAM Registry Hive
///   - SYSTEM Registry Hive
///
/// # このカテゴリに属するアーティファクトをすべて除外
/// disabled_categories:
///   - FileSystem
///
/// # ── カスタムアーティファクト定義 ─────────────────────────────────────────
///
/// # 埋め込み定義にないアーティファクトを追加、または既存定義を上書き
/// artifacts:
///   - name: "Custom App Log"
///     category: "Custom"
///     target_path: "C:\\MyApp\\logs\\app.log"
///     method: File
///   - name: "Custom NTFS File"
///     category: "Custom"
///     target_path: "%SystemDrive%\\LockedFile.db"
///     method: NTFS
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExternalConfig {
    /// Artifact name whitelist.  Empty = no restriction.
    #[serde(default)]
    pub enabled_artifacts: Vec<String>,

    /// Category blacklist.  Empty = no restriction.
    #[serde(default)]
    pub disabled_categories: Vec<String>,

    /// Custom artifact definitions to add to (or override) the embedded set.
    #[serde(default)]
    pub artifacts: Vec<ArtifactDefinition>,
}

impl ExternalConfig {
    /// Extract the filter portion of this config.
    pub fn into_filter(self) -> (CollectionFilter, Vec<ArtifactDefinition>) {
        (
            CollectionFilter {
                enabled_categories: vec![],
                enabled_artifacts: self.enabled_artifacts,
                disabled_categories: self.disabled_categories,
            },
            self.artifacts,
        )
    }
}

impl CollectionFilter {
    /// `true` when the filter places no restrictions.
    pub fn is_empty(&self) -> bool {
        self.enabled_categories.is_empty()
            && self.enabled_artifacts.is_empty()
            && self.disabled_categories.is_empty()
    }

    /// Return a new filter that combines `self` (lower priority, e.g. from
    /// `config.yaml`) with `override_filter` (higher priority, e.g. from CLI).
    ///
    /// Merge semantics:
    /// - `enabled_categories`: override wins if non-empty; otherwise `self` kept.
    /// - `enabled_artifacts`: override wins if non-empty; otherwise `self` kept.
    /// - `disabled_categories`: union of both lists.
    pub fn merge_override(&self, override_filter: &CollectionFilter) -> CollectionFilter {
        let enabled_categories = if override_filter.enabled_categories.is_empty() {
            self.enabled_categories.clone()
        } else {
            override_filter.enabled_categories.clone()
        };

        let enabled_artifacts = if override_filter.enabled_artifacts.is_empty() {
            self.enabled_artifacts.clone()
        } else {
            override_filter.enabled_artifacts.clone()
        };

        let mut disabled_categories = self.disabled_categories.clone();
        for c in &override_filter.disabled_categories {
            if !disabled_categories
                .iter()
                .any(|x| x.eq_ignore_ascii_case(c))
            {
                disabled_categories.push(c.clone());
            }
        }

        CollectionFilter {
            enabled_categories,
            enabled_artifacts,
            disabled_categories,
        }
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Load the filtered artifact list ready for collection.
///
/// Steps:
/// 1. Parse all embedded YAML definitions.
/// 2. Load `<exe_dir>/config.yaml` if present.
/// 3. Merge custom artifact definitions from `config.yaml` into the embedded
///    set (custom entries with the same `name` override the embedded one).
/// 4. Merge filters: `config.yaml` filter < `cli_filter` (CLI wins).
/// 5. Return only artifacts that pass the combined filter.
pub fn load_artifacts(
    exe_dir: &Path,
    cli_filter: Option<&CollectionFilter>,
) -> Result<Vec<ArtifactDefinition>> {
    let mut defs = load_embedded()?;

    let (file_filter, custom_defs) = match load_external_config(exe_dir)? {
        Some(ext) => ext.into_filter(),
        None => (CollectionFilter::default(), vec![]),
    };

    // Merge custom definitions: override by name, then append new ones.
    for custom in custom_defs {
        if let Some(existing) = defs.iter_mut().find(|d| d.name.eq_ignore_ascii_case(&custom.name)) {
            *existing = custom;
        } else {
            defs.push(custom);
        }
    }

    let effective = match cli_filter {
        Some(cli) => file_filter.merge_override(cli),
        None => file_filter,
    };

    Ok(if effective.is_empty() {
        defs
    } else {
        apply_filter(defs, &effective)
    })
}

/// Apply a `CollectionFilter` to a list of definitions and return the survivors.
///
/// Exported so that Phase 5 CLI can run a `--dry-run` preview without going
/// through the full `load_artifacts` path.
pub fn apply_filter(
    defs: Vec<ArtifactDefinition>,
    filter: &CollectionFilter,
) -> Vec<ArtifactDefinition> {
    // Step 1: category whitelist (CLI --category Foo)
    let after_cat_whitelist: Vec<ArtifactDefinition> = if filter.enabled_categories.is_empty() {
        defs
    } else {
        defs.into_iter()
            .filter(|d| {
                filter
                    .enabled_categories
                    .iter()
                    .any(|c| c.eq_ignore_ascii_case(&d.category))
            })
            .collect()
    };

    // Step 2: artifact name whitelist (config.yaml enabled_artifacts)
    let after_whitelist: Vec<ArtifactDefinition> = if filter.enabled_artifacts.is_empty() {
        after_cat_whitelist
    } else {
        after_cat_whitelist
            .into_iter()
            .filter(|d| {
                filter
                    .enabled_artifacts
                    .iter()
                    .any(|n| n.eq_ignore_ascii_case(&d.name))
            })
            .collect()
    };

    // Step 3: category blacklist (CLI --category !Foo)
    if filter.disabled_categories.is_empty() {
        after_whitelist
    } else {
        after_whitelist
            .into_iter()
            .filter(|d| {
                !filter
                    .disabled_categories
                    .iter()
                    .any(|c| c.eq_ignore_ascii_case(&d.category))
            })
            .collect()
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Parse every embedded YAML source into a flat `Vec<ArtifactDefinition>`.
fn load_embedded() -> Result<Vec<ArtifactDefinition>> {
    let mut defs = Vec::new();
    for (name, src) in EMBEDDED_SOURCES {
        let parsed: Vec<ArtifactDefinition> = serde_yaml::from_str(src)
            .with_context(|| format!("failed to parse embedded artifact file '{name}'"))?;
        defs.extend(parsed);
    }
    Ok(defs)
}

/// Read `<exe_dir>/config.yaml` and parse it as an [`ExternalConfig`].
/// Returns `None` if the file does not exist (not an error).
fn load_external_config(exe_dir: &Path) -> Result<Option<ExternalConfig>> {
    let path = exe_dir.join("config.yaml");
    if !path.exists() {
        return Ok(None);
    }

    let contents = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read '{}'", path.display()))?;

    let config: ExternalConfig = serde_yaml::from_str(&contents)
        .with_context(|| format!("failed to parse '{}' as ExternalConfig", path.display()))?;

    Ok(Some(config))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Embedded loading ──────────────────────────────────────────────────────

    #[test]
    fn embedded_defs_are_non_empty() {
        let defs = load_embedded().unwrap();
        assert!(!defs.is_empty(), "embedded YAML sources should contain definitions");
    }

    #[test]
    fn embedded_defs_contain_known_artifacts() {
        let defs = load_embedded().unwrap();
        let names: Vec<&str> = defs.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"SAM Registry Hive"));
        assert!(names.contains(&"Security Event Log"));
    }

    // ── Filter: whitelist ─────────────────────────────────────────────────────

    #[test]
    fn whitelist_keeps_only_named_artifacts() {
        let defs = load_embedded().unwrap();
        let filter = CollectionFilter {
            enabled_artifacts: vec!["SAM Registry Hive".to_owned()],
            ..Default::default()
        };
        let result = apply_filter(defs, &filter);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "SAM Registry Hive");
    }

    #[test]
    fn whitelist_is_case_insensitive() {
        let defs = load_embedded().unwrap();
        let filter = CollectionFilter {
            enabled_artifacts: vec!["sam registry hive".to_owned()],
            ..Default::default()
        };
        let result = apply_filter(defs, &filter);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn empty_whitelist_keeps_all() {
        let defs = load_embedded().unwrap();
        let total = defs.len();
        let filter = CollectionFilter::default();
        let result = apply_filter(defs, &filter);
        assert_eq!(result.len(), total);
    }

    // ── Filter: blacklist ─────────────────────────────────────────────────────

    #[test]
    fn blacklist_removes_category() {
        let defs = load_embedded().unwrap();
        let total = defs.len();
        let eventlog_count = defs.iter().filter(|d| d.category == "EventLogs").count();
        let filter = CollectionFilter {
            disabled_categories: vec!["EventLogs".to_owned()],
            ..Default::default()
        };
        let result = apply_filter(defs, &filter);
        assert_eq!(result.len(), total - eventlog_count);
        assert!(result.iter().all(|d| d.category != "EventLogs"));
    }

    #[test]
    fn blacklist_is_case_insensitive() {
        let _defs = load_embedded().unwrap();
        let filter_lower = CollectionFilter {
            disabled_categories: vec!["eventlogs".to_owned()],
            ..Default::default()
        };
        let filter_upper = CollectionFilter {
            disabled_categories: vec!["EVENTLOGS".to_owned()],
            ..Default::default()
        };
        assert_eq!(
            apply_filter(load_embedded().unwrap(), &filter_lower).len(),
            apply_filter(load_embedded().unwrap(), &filter_upper).len()
        );
    }

    // ── Filter: whitelist + blacklist interaction ─────────────────────────────

    #[test]
    fn blacklist_overrides_whitelist() {
        // Explicitly enable an artifact but also disable its category —
        // the blacklist should win and the artifact should be excluded.
        let defs = load_embedded().unwrap();
        let filter = CollectionFilter {
            enabled_artifacts: vec!["Security Event Log".to_owned()],
            disabled_categories: vec!["EventLogs".to_owned()],
            ..Default::default()
        };
        let result = apply_filter(defs, &filter);
        assert!(result.is_empty(), "disabled category should override enabled_artifacts");
    }

    // ── merge_override ────────────────────────────────────────────────────────

    #[test]
    fn merge_override_cli_whitelist_wins() {
        let base = CollectionFilter {
            enabled_artifacts: vec!["A".to_owned()],
            ..Default::default()
        };
        let cli = CollectionFilter {
            enabled_artifacts: vec!["B".to_owned()],
            ..Default::default()
        };
        let merged = base.merge_override(&cli);
        assert_eq!(merged.enabled_artifacts, vec!["B"]);
    }

    #[test]
    fn merge_override_empty_cli_keeps_base_whitelist() {
        let base = CollectionFilter {
            enabled_artifacts: vec!["A".to_owned()],
            ..Default::default()
        };
        let cli = CollectionFilter::default();
        let merged = base.merge_override(&cli);
        assert_eq!(merged.enabled_artifacts, vec!["A"]);
    }

    #[test]
    fn merge_override_blacklists_are_unioned() {
        let base = CollectionFilter {
            disabled_categories: vec!["EventLogs".to_owned()],
            ..Default::default()
        };
        let cli = CollectionFilter {
            disabled_categories: vec!["Registry".to_owned()],
            ..Default::default()
        };
        let merged = base.merge_override(&cli);
        assert_eq!(merged.disabled_categories.len(), 2);
    }

    // ── External config (config.yaml) ─────────────────────────────────────────

    #[test]
    fn no_config_yaml_returns_all_embedded() {
        let tmp = std::env::temp_dir().join("rust_cdir_config_test_nofile");
        std::fs::create_dir_all(&tmp).unwrap();
        // No config.yaml in tmp
        let defs = load_artifacts(&tmp, None).unwrap();
        assert_eq!(defs.len(), load_embedded().unwrap().len());
        std::fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn config_yaml_disabled_category_is_applied() {
        let tmp = std::env::temp_dir().join("rust_cdir_config_test_filter");
        std::fs::create_dir_all(&tmp).unwrap();

        let yaml = "disabled_categories:\n  - EventLogs\n";
        std::fs::write(tmp.join("config.yaml"), yaml).unwrap();

        let defs = load_artifacts(&tmp, None).unwrap();
        assert!(defs.iter().all(|d| d.category != "EventLogs"));

        std::fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn config_yaml_enabled_artifacts_is_applied() {
        let tmp = std::env::temp_dir().join("rust_cdir_config_test_whitelist");
        std::fs::create_dir_all(&tmp).unwrap();

        let yaml = "enabled_artifacts:\n  - SAM Registry Hive\n";
        std::fs::write(tmp.join("config.yaml"), yaml).unwrap();

        let defs = load_artifacts(&tmp, None).unwrap();
        assert_eq!(defs.len(), 1);
        assert_eq!(defs[0].name, "SAM Registry Hive");

        std::fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn cli_filter_overrides_config_yaml() {
        let tmp = std::env::temp_dir().join("rust_cdir_config_test_cli");
        std::fs::create_dir_all(&tmp).unwrap();

        // config.yaml wants only EventLogs
        let yaml = "enabled_artifacts:\n  - Security Event Log\n";
        std::fs::write(tmp.join("config.yaml"), yaml).unwrap();

        // CLI overrides to only SAM
        let cli = CollectionFilter {
            enabled_artifacts: vec!["SAM Registry Hive".to_owned()],
            ..Default::default()
        };
        let defs = load_artifacts(&tmp, Some(&cli)).unwrap();
        assert_eq!(defs.len(), 1);
        assert_eq!(defs[0].name, "SAM Registry Hive");

        std::fs::remove_dir_all(&tmp).unwrap();
    }

    // ── Custom artifact definitions in config.yaml ────────────────────────────

    #[test]
    fn config_yaml_custom_artifact_is_added() {
        let tmp = std::env::temp_dir().join("rust_cdir_config_test_custom_add");
        std::fs::create_dir_all(&tmp).unwrap();

        let yaml = r#"
artifacts:
  - name: "My Custom Log"
    category: "Custom"
    target_path: "C:\\MyApp\\app.log"
    method: File
"#;
        std::fs::write(tmp.join("config.yaml"), yaml).unwrap();

        let embedded_count = load_embedded().unwrap().len();
        let defs = load_artifacts(&tmp, None).unwrap();
        assert_eq!(defs.len(), embedded_count + 1);
        assert!(defs.iter().any(|d| d.name == "My Custom Log"));

        std::fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn config_yaml_custom_artifact_overrides_embedded() {
        let tmp = std::env::temp_dir().join("rust_cdir_config_test_custom_override");
        std::fs::create_dir_all(&tmp).unwrap();

        // Override "SAM Registry Hive" with a different path and method
        let yaml = r#"
artifacts:
  - name: "SAM Registry Hive"
    category: "Registry"
    target_path: "D:\\CustomPath\\SAM"
    method: File
"#;
        std::fs::write(tmp.join("config.yaml"), yaml).unwrap();

        let embedded_count = load_embedded().unwrap().len();
        let defs = load_artifacts(&tmp, None).unwrap();
        // Total count stays the same — override, not addition
        assert_eq!(defs.len(), embedded_count);
        let sam = defs.iter().find(|d| d.name == "SAM Registry Hive").unwrap();
        assert_eq!(sam.target_path, "D:\\CustomPath\\SAM");

        std::fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn config_yaml_custom_artifact_override_is_case_insensitive() {
        let tmp = std::env::temp_dir().join("rust_cdir_config_test_custom_override_ci");
        std::fs::create_dir_all(&tmp).unwrap();

        let yaml = r#"
artifacts:
  - name: "sam registry hive"
    category: "Registry"
    target_path: "D:\\AltPath\\SAM"
    method: File
"#;
        std::fs::write(tmp.join("config.yaml"), yaml).unwrap();

        let embedded_count = load_embedded().unwrap().len();
        let defs = load_artifacts(&tmp, None).unwrap();
        assert_eq!(defs.len(), embedded_count);

        std::fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn config_yaml_custom_artifact_included_in_filter() {
        let tmp = std::env::temp_dir().join("rust_cdir_config_test_custom_filter");
        std::fs::create_dir_all(&tmp).unwrap();

        // Add a custom artifact and whitelist only it
        let yaml = r#"
enabled_artifacts:
  - "My App Log"
artifacts:
  - name: "My App Log"
    category: "Custom"
    target_path: "C:\\App\\app.log"
    method: File
"#;
        std::fs::write(tmp.join("config.yaml"), yaml).unwrap();

        let defs = load_artifacts(&tmp, None).unwrap();
        assert_eq!(defs.len(), 1);
        assert_eq!(defs[0].name, "My App Log");

        std::fs::remove_dir_all(&tmp).unwrap();
    }
}
