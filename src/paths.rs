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

/// Final guard: canonicalized real path must stay within `base`.
fn contained(base: &Path, candidate: &Path) -> Result<PathBuf, PathError> {
    let base_c = base.canonicalize().map_err(|_| PathError::NotFound)?;
    // Canonicalize the existing ancestor, then re-join the non-existent tail,
    // so resolution also defeats symlink escapes.
    let resolved = match candidate.canonicalize() {
        Ok(p) => p,
        Err(_) => candidate.to_path_buf(),
    };
    if resolved.starts_with(&base_c) {
        Ok(resolved)
    } else {
        Err(PathError::Traversal)
    }
}

impl ScopeMap {
    pub fn single(root: PathBuf) -> Self {
        ScopeMap { roots: BTreeMap::new(), single: Some(root) }
    }

    pub fn multi(roots: BTreeMap<String, PathBuf>) -> Self {
        ScopeMap { roots, single: None }
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
        let got = m.resolve(std::path::Path::new("/2026-06-19/clip.mp4")).unwrap();
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
        assert_eq!(m.list_root(), vec!["driveway".to_string(), "front-door".to_string()]);
    }

    #[test]
    fn multi_root_maps_first_component_to_real_dir() {
        let (_d, cam) = fixture();
        let mut roots = BTreeMap::new();
        roots.insert("front-door".to_string(), cam.clone());
        let m = ScopeMap::multi(roots);
        let got = m.resolve(std::path::Path::new("/front-door/2026-06-19/clip.mp4")).unwrap();
        assert_eq!(got, cam.join("2026-06-19/clip.mp4"));
    }

    #[test]
    fn multi_root_rejects_unknown_camera() {
        let (_d, cam) = fixture();
        let mut roots = BTreeMap::new();
        roots.insert("front-door".to_string(), cam);
        let m = ScopeMap::multi(roots);
        assert_eq!(m.resolve(std::path::Path::new("/driveway/x")).unwrap_err(), PathError::OutsideScope);
    }
}
