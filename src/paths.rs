//! Pure path scoping & jail containment for viewer accounts.
use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

#[derive(Debug, PartialEq, Eq)]
pub enum PathError {
    Traversal,
    NotFound,
    OutsideScope,
}

#[derive(Debug, Clone)]
pub struct ScopeMap {
    roots: BTreeMap<String, PathBuf>,
    single: Option<PathBuf>,
}

/// Reject any virtual path containing `..` or rooted escapes before mapping.
fn normalize(virtual_path: &Path) -> Result<Vec<String>, PathError> {
    let mut out = Vec::new();
    for comp in virtual_path.components() {
        match comp {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(s) => out.push(s.to_string_lossy().into_owned()),
            Component::ParentDir | Component::Prefix(_) => return Err(PathError::Traversal),
        }
    }
    Ok(out)
}

/// Final guard: the real path the request resolves to must stay within `base`.
/// Resolves symlinks by canonicalizing the longest existing ancestor and
/// re-joining the (non-existent) tail, so a symlinked intermediate directory
/// cannot escape the jail even when the leaf does not yet exist.
fn contained(base: &Path, candidate: &Path) -> Result<PathBuf, PathError> {
    let base_c = base.canonicalize().map_err(|_| PathError::NotFound)?;

    // Fast path: the whole candidate exists — canonicalize resolves every symlink.
    if let Ok(resolved) = candidate.canonicalize() {
        return if resolved.starts_with(&base_c) {
            Ok(resolved)
        } else {
            Err(PathError::Traversal)
        };
    }

    // Slow path: the leaf (or a deeper component) does not exist. Canonicalize
    // the longest existing ancestor — which resolves any symlinks within it —
    // then re-attach the non-existent tail and check containment.
    let mut ancestor = candidate.to_path_buf();
    let mut tail = PathBuf::new();
    loop {
        if let Ok(canon) = ancestor.canonicalize() {
            let resolved = canon.join(&tail);
            return if resolved.starts_with(&base_c) {
                Ok(resolved)
            } else {
                Err(PathError::Traversal)
            };
        }
        match ancestor.file_name() {
            Some(name) => {
                // Use push to avoid a trailing slash when tail is empty.
                let mut new_tail = PathBuf::from(name);
                if tail != PathBuf::new() {
                    new_tail.push(&tail);
                }
                tail = new_tail;
                ancestor.pop();
            }
            None => return Err(PathError::NotFound),
        }
    }
}

impl ScopeMap {
    pub fn single(root: PathBuf) -> Self {
        ScopeMap {
            roots: BTreeMap::new(),
            single: Some(root),
        }
    }

    pub fn multi(roots: BTreeMap<String, PathBuf>) -> Self {
        ScopeMap {
            roots,
            single: None,
        }
    }

    pub fn list_root(&self) -> Vec<String> {
        self.roots.keys().cloned().collect()
    }

    pub fn resolve(&self, virtual_path: &Path) -> Result<PathBuf, PathError> {
        let parts = normalize(virtual_path)?;
        if let Some(base) = &self.single {
            let joined = parts.iter().fold(base.clone(), |acc, p| acc.join(p));
            return contained(base, &joined);
        }
        let mut iter = parts.into_iter();
        let cam = iter.next().ok_or(PathError::OutsideScope)?;
        let base = self.roots.get(&cam).ok_or(PathError::OutsideScope)?;
        let joined = iter.fold(base.clone(), |acc, p| acc.join(p));
        contained(base, &joined)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::PathBuf;

    fn fixture() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let cam = dir.path().join("front-door");
        fs::create_dir_all(cam.join("2026-06-19")).unwrap();
        fs::write(cam.join("2026-06-19/clip.mp4"), b"data").unwrap();
        (dir, cam)
    }

    #[test]
    fn single_root_resolves_inside() {
        let (_d, cam) = fixture();
        let m = ScopeMap::single(cam.clone());
        let got = m
            .resolve(std::path::Path::new("/2026-06-19/clip.mp4"))
            .unwrap();
        assert_eq!(got, cam.join("2026-06-19/clip.mp4"));
    }

    #[test]
    fn single_root_rejects_parent_traversal() {
        let (_d, cam) = fixture();
        let m = ScopeMap::single(cam);
        let err = m.resolve(std::path::Path::new("/../secret")).unwrap_err();
        assert_eq!(err, PathError::Traversal);
    }

    #[test]
    fn multi_root_lists_only_allowed_names() {
        let (d, cam) = fixture();
        let mut roots = BTreeMap::new();
        roots.insert("front-door".to_string(), cam);
        roots.insert("driveway".to_string(), d.path().join("driveway"));
        let m = ScopeMap::multi(roots);
        assert_eq!(
            m.list_root(),
            vec!["driveway".to_string(), "front-door".to_string()]
        );
    }

    #[test]
    fn multi_root_maps_first_component_to_real_dir() {
        let (_d, cam) = fixture();
        let mut roots = BTreeMap::new();
        roots.insert("front-door".to_string(), cam.clone());
        let m = ScopeMap::multi(roots);
        let got = m
            .resolve(std::path::Path::new("/front-door/2026-06-19/clip.mp4"))
            .unwrap();
        assert_eq!(got, cam.join("2026-06-19/clip.mp4"));
    }

    #[test]
    fn multi_root_rejects_unknown_camera() {
        let (_d, cam) = fixture();
        let mut roots = BTreeMap::new();
        roots.insert("front-door".to_string(), cam);
        let m = ScopeMap::multi(roots);
        assert_eq!(
            m.resolve(std::path::Path::new("/driveway/x")).unwrap_err(),
            PathError::OutsideScope
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_escape_existing_target() {
        let (_d, cam) = fixture();
        let outside = tempfile::tempdir().unwrap(); // unambiguously outside the jail
        std::os::unix::fs::symlink(outside.path(), cam.join("escape")).unwrap();
        let m = ScopeMap::single(cam);
        // Resolving the symlink itself must escape -> Traversal.
        assert_eq!(
            m.resolve(std::path::Path::new("/escape")).unwrap_err(),
            PathError::Traversal
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_escape_nonexistent_leaf() {
        let (_d, cam) = fixture();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), cam.join("escape")).unwrap();
        let m = ScopeMap::single(cam);
        // A non-existent leaf behind the symlink must STILL be rejected (the bug).
        assert_eq!(
            m.resolve(std::path::Path::new("/escape/definitely-not-here-1234"))
                .unwrap_err(),
            PathError::Traversal
        );
    }
}
