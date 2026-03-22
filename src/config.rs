//! Artifact definition management.
//!
//! Standard definitions are **embedded in the binary** at compile time via
//! `include_str!`, so the tool works as a single executable without needing
//! the `artifacts/` directory at runtime.
//!
//! An optional `config.yaml` placed beside the executable lets operators
//! filter which artifacts are collected without rebuilding the binary.
//!
//! Resolution order (highest priority first):
//!   1. CLI `CollectionFilter` (Phase 5 — passed as `Some(&filter)`)
//!   2. `<exe_dir>/config.yaml`
//!   3. Embedded defaults (all artifacts collected)

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

// ── Embedded YAML sources ─────────────────────────────────────────────────────

const EMBEDDED_EVENTLOGS: &str = include_str!("../artifacts/windows_eventlogs.yaml");
const EMBEDDED_REGISTRY: &str = include_str!("../artifacts/windows_registry.yaml");
const EMBEDDED_FILESYSTEM: &str = include_str!("../artifacts/windows_filesystem.yaml");

/// All embedded artifact YAML sources, in load order.
static EMBEDDED_SOURCES: &[(&str, &str)] = &[
    ("windows_eventlogs.yaml", EMBEDDED_EVENTLOGS),
    ("windows_registry.yaml", EMBEDDED_REGISTRY),
    ("windows_filesystem.yaml", EMBEDDED_FILESYSTEM),
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
}

// ── Filter type ───────────────────────────────────────────────────────────────

/// Criteria for selecting which artifacts to collect.
///
/// Used both by the external `config.yaml` and (in Phase 5) by CLI flags.
///
/// ### Filtering rules (applied in order)
///
/// 1. **Whitelist** (`enabled_artifacts`): if non-empty, only artifacts whose
///    `name` appears in this list are kept.  Case-insensitive.
/// 2. **Blacklist** (`disabled_categories`): artifacts whose `category` appears
///    in this list are removed.  Case-insensitive.  Applied *after* the
///    whitelist, so it can further restrict an explicit whitelist.
///
/// An empty filter (both lists empty) is a no-op — all artifacts are kept.
///
/// ### `config.yaml` example
///
/// ```yaml
/// # Collect only these artifacts:
/// enabled_artifacts:
///   - SAM Registry Hive
///   - SYSTEM Registry Hive
///
/// # …but never collect anything in the EventLogs category:
/// disabled_categories:
///   - EventLogs
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CollectionFilter {
    /// Artifact name whitelist.  Empty = no restriction.
    #[serde(default)]
    pub enabled_artifacts: Vec<String>,

    /// Category blacklist.  Empty = no restriction.
    #[serde(default)]
    pub disabled_categories: Vec<String>,
}

impl CollectionFilter {
    /// `true` when the filter places no restrictions.
    pub fn is_empty(&self) -> bool {
        self.enabled_artifacts.is_empty() && self.disabled_categories.is_empty()
    }

    /// Return a new filter that combines `self` (lower priority, e.g. from
    /// `config.yaml`) with `override_filter` (higher priority, e.g. from CLI).
    ///
    /// Merge semantics:
    /// - `enabled_artifacts`: the override wins if non-empty; otherwise `self`
    ///   is kept.
    /// - `disabled_categories`: union of both lists (either source can disable
    ///   a category).
    pub fn merge_override(&self, override_filter: &CollectionFilter) -> CollectionFilter {
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
/// 3. Merge with `cli_filter` (CLI wins over `config.yaml`).
/// 4. Return only artifacts that pass the combined filter.
///
/// Pass `cli_filter: None` before Phase 5 CLI is implemented.
pub fn load_artifacts(
    exe_dir: &Path,
    cli_filter: Option<&CollectionFilter>,
) -> Result<Vec<ArtifactDefinition>> {
    let defs = load_embedded()?;

    let file_filter = load_external_config(exe_dir)?;

    let effective = match (file_filter, cli_filter) {
        (Some(f), Some(cli)) => f.merge_override(cli),
        (Some(f), None) => f,
        (None, Some(cli)) => cli.clone(),
        (None, None) => CollectionFilter::default(),
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
    // Step 1: whitelist
    let after_whitelist: Vec<ArtifactDefinition> = if filter.enabled_artifacts.is_empty() {
        defs
    } else {
        defs.into_iter()
            .filter(|d| {
                filter
                    .enabled_artifacts
                    .iter()
                    .any(|n| n.eq_ignore_ascii_case(&d.name))
            })
            .collect()
    };

    // Step 2: blacklist
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

/// Read `<exe_dir>/config.yaml` and parse it as a `CollectionFilter`.
/// Returns `None` if the file does not exist (not an error).
fn load_external_config(exe_dir: &Path) -> Result<Option<CollectionFilter>> {
    let path = exe_dir.join("config.yaml");
    if !path.exists() {
        return Ok(None);
    }

    let contents = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read '{}'", path.display()))?;

    let filter: CollectionFilter = serde_yaml::from_str(&contents)
        .with_context(|| format!("failed to parse '{}' as CollectionFilter", path.display()))?;

    Ok(Some(filter))
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
            disabled_categories: vec![],
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
            disabled_categories: vec![],
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
            enabled_artifacts: vec![],
            disabled_categories: vec!["EventLogs".to_owned()],
        };
        let result = apply_filter(defs, &filter);
        assert_eq!(result.len(), total - eventlog_count);
        assert!(result.iter().all(|d| d.category != "EventLogs"));
    }

    #[test]
    fn blacklist_is_case_insensitive() {
        let _defs = load_embedded().unwrap();
        let filter_lower = CollectionFilter {
            enabled_artifacts: vec![],
            disabled_categories: vec!["eventlogs".to_owned()],
        };
        let filter_upper = CollectionFilter {
            enabled_artifacts: vec![],
            disabled_categories: vec!["EVENTLOGS".to_owned()],
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
        };
        let result = apply_filter(defs, &filter);
        assert!(result.is_empty(), "disabled category should override enabled_artifacts");
    }

    // ── merge_override ────────────────────────────────────────────────────────

    #[test]
    fn merge_override_cli_whitelist_wins() {
        let base = CollectionFilter {
            enabled_artifacts: vec!["A".to_owned()],
            disabled_categories: vec![],
        };
        let cli = CollectionFilter {
            enabled_artifacts: vec!["B".to_owned()],
            disabled_categories: vec![],
        };
        let merged = base.merge_override(&cli);
        assert_eq!(merged.enabled_artifacts, vec!["B"]);
    }

    #[test]
    fn merge_override_empty_cli_keeps_base_whitelist() {
        let base = CollectionFilter {
            enabled_artifacts: vec!["A".to_owned()],
            disabled_categories: vec![],
        };
        let cli = CollectionFilter::default();
        let merged = base.merge_override(&cli);
        assert_eq!(merged.enabled_artifacts, vec!["A"]);
    }

    #[test]
    fn merge_override_blacklists_are_unioned() {
        let base = CollectionFilter {
            enabled_artifacts: vec![],
            disabled_categories: vec!["EventLogs".to_owned()],
        };
        let cli = CollectionFilter {
            enabled_artifacts: vec![],
            disabled_categories: vec!["Registry".to_owned()],
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
            disabled_categories: vec![],
        };
        let defs = load_artifacts(&tmp, Some(&cli)).unwrap();
        assert_eq!(defs.len(), 1);
        assert_eq!(defs[0].name, "SAM Registry Hive");

        std::fs::remove_dir_all(&tmp).unwrap();
    }
}
