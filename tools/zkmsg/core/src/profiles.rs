//! Root-`.zkmsg` profile layout (spec 2026-07-08): discovery,
//! home classification, `current` bookkeeping, and the one-time
//! legacy migration. Pure filesystem logic — no network, ever.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};

use crate::config::Home;

pub const PROFILE_PREFIX: &str = ".zkmsg-";

/// Directory entries a legacy root profile carries; migration moves
/// each that exists into the new `.zkmsg-<name>` child.
const ROOT_ENTRIES: [&str; 5] = ["config.json", "keys.json", "sends", "inbox.json", "proofs"];

#[derive(Debug, Clone)]
pub struct ProfileEntry {
    pub name: String,
    pub dir: PathBuf,
    /// Registered handle cached in this profile's keys.json, if any.
    pub handle: Option<String>,
    /// setup.json present but config.json absent — a wizard run to resume.
    pub setup_incomplete: bool,
}

pub fn list_profiles(root: &Path) -> Result<Vec<ProfileEntry>> {
    let mut out = vec![];
    if !root.is_dir() {
        return Ok(out);
    }
    for entry in fs::read_dir(root)? {
        let dir = entry?.path();
        let Some(fname) = dir.file_name().and_then(|s| s.to_str()) else { continue };
        let Some(name) = fname.strip_prefix(PROFILE_PREFIX) else { continue };
        if !dir.is_dir() || name.is_empty() {
            continue;
        }
        let has_config = dir.join("config.json").is_file();
        let has_setup = dir.join("setup.json").is_file();
        if !has_config && !has_setup {
            continue;
        }
        let handle = Home::new(dir.clone()).load_keys().ok().and_then(|k| k.handle);
        out.push(ProfileEntry {
            name: name.to_string(),
            dir,
            handle,
            setup_incomplete: !has_config && has_setup,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

pub fn read_current(root: &Path) -> Option<String> {
    let s = fs::read_to_string(root.join("current")).ok()?;
    let s = s.trim().to_string();
    (!s.is_empty()).then_some(s)
}

pub fn write_current(root: &Path, name: &str) -> Result<()> {
    fs::create_dir_all(root)?;
    fs::write(root.join("current"), name).context("writing current")
}

#[derive(Debug)]
pub enum HomeKind {
    /// Has a config.json — a concrete home, usable directly.
    Profile(PathBuf),
    /// Contains profile children and/or a `current` file.
    Root { root: PathBuf, current: Option<PathBuf> },
    /// Neither — preserves today's "no config — run `zkmsg init`" path.
    Empty(PathBuf),
}

pub fn classify_home(path: &Path) -> HomeKind {
    if path.join("config.json").is_file() {
        return HomeKind::Profile(path.to_path_buf());
    }
    let profiles = list_profiles(path).unwrap_or_default();
    if !profiles.is_empty() || path.join("current").is_file() {
        let current = read_current(path)
            .map(|n| path.join(format!("{PROFILE_PREFIX}{n}")))
            .filter(|p| p.join("config.json").is_file());
        return HomeKind::Root { root: path.to_path_buf(), current };
    }
    HomeKind::Empty(path.to_path_buf())
}

/// CLI-facing resolution: a profile passes through; a root follows its
/// `current` file; an empty path passes through (so `init` still works).
pub fn resolve_cli_home(path: &Path) -> Result<PathBuf> {
    match classify_home(path) {
        HomeKind::Profile(p) | HomeKind::Empty(p) => Ok(p),
        HomeKind::Root { root, current: Some(p) } => {
            let _ = root;
            Ok(p)
        }
        HomeKind::Root { root, current: None } => bail!(
            "{} is a profile root with no valid current profile — pass --home {}/{PROFILE_PREFIX}<name> or pick one in the GUI",
            root.display(),
            root.display(),
        ),
    }
}

#[derive(Debug, Clone)]
pub struct LegacySource {
    pub dir: PathBuf,
    pub is_root: bool,
    pub suggested_name: String,
}

/// Reads the cached handle from a home's `keys.json`, if present.
fn cached_handle(dir: &Path) -> Option<String> {
    Home::new(dir.to_path_buf()).load_keys().ok().and_then(|k| k.handle)
}

/// Finds legacy homes to migrate: the old flat `root/config.json`
/// (the `is_root` source) plus any `.zkmsg-*` siblings that carry a
/// `config.json` but live beside `root` rather than inside it.
pub fn detect_legacy(root: &Path) -> Vec<LegacySource> {
    let mut out = vec![];
    if root.join("config.json").is_file() {
        out.push(LegacySource {
            dir: root.to_path_buf(),
            is_root: true,
            suggested_name: cached_handle(root).unwrap_or_default(),
        });
    }
    if let Some(parent) = root.parent() {
        if let Ok(rd) = fs::read_dir(parent) {
            for entry in rd.flatten() {
                let dir = entry.path();
                if dir == root {
                    continue;
                }
                let Some(fname) = dir.file_name().and_then(|s| s.to_str()) else { continue };
                let Some(suffix) = fname.strip_prefix(PROFILE_PREFIX) else { continue };
                if suffix.is_empty() || !dir.join("config.json").is_file() {
                    continue;
                }
                out.push(LegacySource {
                    dir: dir.clone(),
                    is_root: false,
                    suggested_name: cached_handle(&dir).unwrap_or_else(|| suffix.to_string()),
                });
            }
        }
    }
    out
}

#[derive(Debug, Clone)]
pub struct MigrationMove {
    pub from: PathBuf,
    pub to: PathBuf,
}

pub fn plan_migration(root: &Path, named: &[(LegacySource, String)]) -> Result<Vec<MigrationMove>> {
    let mut seen = std::collections::HashSet::new();
    for (_, name) in named {
        ensure!(!name.is_empty(), "migration target name must not be empty");
        ensure!(
            name.is_ascii() && !name.contains('/') && !name.contains('\\'),
            "migration target name {name:?} must be ASCII with no path separators"
        );
        ensure!(seen.insert(name.as_str()), "duplicate migration target name {name:?}");
    }

    let mut moves = vec![];
    for (source, name) in named {
        let target = root.join(format!("{PROFILE_PREFIX}{name}"));
        // The new child must not already exist. Exception: when the root
        // itself becomes a child, its own future path is created by moving
        // entries into it — so it is fine for it not to exist yet, and it
        // must not pre-exist as a populated dir.
        ensure!(
            !target.exists(),
            "target {} already exists — refusing to migrate",
            target.display()
        );
        if source.is_root {
            for entry in ROOT_ENTRIES {
                let from = source.dir.join(entry);
                if from.exists() {
                    moves.push(MigrationMove { from, to: target.join(entry) });
                }
            }
        } else {
            moves.push(MigrationMove { from: source.dir.clone(), to: target });
        }
    }
    Ok(moves)
}

pub fn execute_migration(moves: &[MigrationMove]) -> Result<()> {
    for mv in moves {
        // `exists()` follows symlinks, so a dangling link at `to` would pass
        // the check and `fs::rename` would silently replace it. `symlink_metadata`
        // does not follow, so any entry — including a broken link — refuses.
        ensure!(
            mv.to.symlink_metadata().is_err(),
            "target {} already exists — aborting migration",
            mv.to.display()
        );
        if let Some(parent) = mv.to.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::rename(&mv.from, &mv.to)
            .with_context(|| format!("moving {} -> {}", mv.from.display(), mv.to.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tmp(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("zkmsg-profiles-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }
    fn mk_profile(dir: &std::path::Path, handle: Option<&str>) {
        fs::create_dir_all(dir).unwrap();
        fs::write(dir.join("config.json"), "{}").unwrap();
        if let Some(h) = handle {
            fs::write(
                dir.join("keys.json"),
                format!(r#"{{"scan_priv":"0x1","scan_pub":"0x2","handle":"{h}","leaf_index":0}}"#),
            ).unwrap();
        }
    }

    #[test]
    fn classify_all_three_kinds() {
        let root = tmp("classify");
        // Empty: nothing inside
        assert!(matches!(classify_home(&root), HomeKind::Empty(_)));
        // Root: has a profile child
        mk_profile(&root.join(".zkmsg-alice"), Some("alice"));
        write_current(&root, "alice").unwrap();
        match classify_home(&root) {
            HomeKind::Root { current: Some(p), .. } => assert!(p.ends_with(".zkmsg-alice")),
            other => panic!("expected Root with current, got {other:?}"),
        }
        // Profile: config.json directly inside
        let prof = tmp("classify-prof");
        mk_profile(&prof, None);
        assert!(matches!(classify_home(&prof), HomeKind::Profile(_)));
        fs::remove_dir_all(&root).unwrap();
        fs::remove_dir_all(&prof).unwrap();
    }

    #[test]
    fn list_profiles_reads_handles_and_sorts() {
        let root = tmp("list");
        mk_profile(&root.join(".zkmsg-bob"), Some("bob"));
        mk_profile(&root.join(".zkmsg-alice"), Some("alice"));
        fs::create_dir_all(root.join(".zkmsg-half")).unwrap(); // no config.json, no setup.json → ignored
        let got = list_profiles(&root).unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!((got[0].name.as_str(), got[0].handle.as_deref()), ("alice", Some("alice")));
        assert_eq!(got[1].name.as_str(), "bob");
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn list_profiles_surfaces_incomplete_setups() {
        let root = tmp("incomplete");
        let half = root.join(".zkmsg-carol");
        fs::create_dir_all(&half).unwrap();
        fs::write(half.join("setup.json"), "{}").unwrap(); // wizard checkpoint, no config yet
        let got = list_profiles(&root).unwrap();
        assert_eq!(got.len(), 1);
        assert!(got[0].setup_incomplete);
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn detect_legacy_finds_root_and_siblings() {
        let parent = tmp("legacy");
        let root = parent.join(".zkmsg");
        mk_profile(&root, Some("alice"));                        // legacy: config.json at root
        mk_profile(&parent.join(".zkmsg-bob"), Some("bob"));     // legacy sibling
        let found = detect_legacy(&root);
        assert_eq!(found.len(), 2);
        let root_src = found.iter().find(|s| s.is_root).unwrap();
        assert_eq!(root_src.suggested_name, "alice");            // from keys.json handle
        let sib = found.iter().find(|s| !s.is_root).unwrap();
        assert_eq!(sib.suggested_name, "bob");
        fs::remove_dir_all(&parent).unwrap();
    }

    #[test]
    fn migration_plans_moves_and_refuses_collisions() {
        let parent = tmp("migrate");
        let root = parent.join(".zkmsg");
        mk_profile(&root, Some("alice"));
        fs::create_dir_all(root.join("sends")).unwrap();
        mk_profile(&parent.join(".zkmsg-bob"), Some("bob"));
        let sources = detect_legacy(&root);
        let named: Vec<_> =
            sources.into_iter().map(|s| { let n = s.suggested_name.clone(); (s, n) }).collect();

        // duplicate names refused
        let dup: Vec<_> = named.iter().map(|(s, _)| (s.clone(), "same".to_string())).collect();
        assert!(plan_migration(&root, &dup).is_err());

        let moves = plan_migration(&root, &named).unwrap();
        execute_migration(&moves).unwrap();
        // legacy root entries moved into the alice child; bob dir moved under root
        assert!(root.join(".zkmsg-alice/config.json").exists());
        assert!(root.join(".zkmsg-alice/keys.json").exists());
        assert!(root.join(".zkmsg-alice/sends").exists());
        assert!(root.join(".zkmsg-bob/config.json").exists());
        assert!(!root.join("config.json").exists());
        assert!(!parent.join(".zkmsg-bob").exists());
        // and the result classifies as a Root with 2 profiles
        assert_eq!(list_profiles(&root).unwrap().len(), 2);

        // re-running the plan against the migrated tree collides → error, nothing touched
        let again = detect_legacy(&root);
        assert!(again.is_empty());
        fs::remove_dir_all(&parent).unwrap();
    }

    #[test]
    fn execute_migration_refuses_dangling_symlink_target() {
        let dir = tmp("dangling");
        let from = dir.join("src");
        mk_profile(&from, None);
        // A dangling symlink at `to`: `exists()` returns false (target is
        // missing), but the entry is present and must not be clobbered.
        let to = dir.join(".zkmsg-x");
        std::os::unix::fs::symlink(dir.join("nonexistent"), &to).unwrap();
        assert!(!to.exists()); // dangling: follows to a missing target
        let moves = vec![MigrationMove { from: from.clone(), to: to.clone() }];
        assert!(execute_migration(&moves).is_err());
        // The source is untouched and the link is still there (not replaced).
        assert!(from.join("config.json").exists());
        assert!(to.symlink_metadata().is_ok());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn resolve_cli_home_all_kinds() {
        let root = tmp("resolve");
        mk_profile(&root.join(".zkmsg-alice"), None);
        write_current(&root, "alice").unwrap();
        assert!(resolve_cli_home(&root).unwrap().ends_with(".zkmsg-alice"));
        let prof = root.join(".zkmsg-alice");
        assert_eq!(resolve_cli_home(&prof).unwrap(), prof);   // profile dirs pass through
        fs::write(root.join("current"), "ghost").unwrap();
        assert!(resolve_cli_home(&root).is_err());            // current names a missing profile
        fs::remove_dir_all(&root).unwrap();
    }
}
