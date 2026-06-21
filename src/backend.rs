//! Append-only `StorageBackend<ReoUser>` for libunftp 0.23 / unftp-core 0.1.
//!
//! Security model:
//! - Uploaders: Put, Mkd, List, Metadata, Cwd only.
//! - Viewers:   Get, List, Metadata, Cwd only.
//! - Del / Rmd / Rename: denied for all roles.
//! - put enforces non-overlap byte-level append via `store_stream`.
//! - Reolink test files go to quarantine dir (overwrite allowed, no finalize).
//! - list hides staging files and the quarantine directory.
//! - Viewer listing `/` synthesizes dirs from multi-root scope.

use crate::account::Role;
use crate::append::{self, QUARANTINE_DIR, STAGING_SUFFIX};
use crate::auth::ReoUser;
use crate::paths::{PathError, ScopeMap};
use async_trait::async_trait;
use std::fmt::Debug;
use std::io::SeekFrom;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use tokio::io::AsyncSeekExt;
use unftp_core::storage::{Error, ErrorKind, Fileinfo, Metadata, Result, StorageBackend};

// ---------------------------------------------------------------------------
// Capability gate
// ---------------------------------------------------------------------------

/// All operations a client may attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    Get,
    Put,
    List,
    Metadata,
    Cwd,
    Mkd,
    Del,
    Rmd,
    Rename,
}

/// Returns `true` when `role` may perform `op`.
///
/// Uploaders: Put, Mkd, List, Metadata, Cwd.
/// Viewers:   Get, List, Metadata, Cwd.
/// Everything else denied.
pub fn capability_allowed(role: &Role, op: Op) -> bool {
    use Op::*;
    match role {
        Role::Uploader { .. } => matches!(op, Put | Mkd | List | Metadata | Cwd),
        Role::Viewer { .. } => matches!(op, Get | List | Metadata | Cwd),
    }
}

// ---------------------------------------------------------------------------
// ScopeMap projection
// ---------------------------------------------------------------------------

/// Map a `ReoUser` to the `ScopeMap` that governs its filesystem view.
pub fn user_view(user: &ReoUser) -> ScopeMap {
    match &user.role {
        Role::Uploader { home } => ScopeMap::single(home.clone()),
        Role::Viewer { scope } => scope.clone(),
    }
}

// ---------------------------------------------------------------------------
// PathError → storage Error mapping
// ---------------------------------------------------------------------------

fn path_err_to_storage(e: PathError) -> Error {
    match e {
        PathError::Traversal | PathError::OutsideScope => ErrorKind::PermissionDenied.into(),
        PathError::NotFound => ErrorKind::PermanentFileNotAvailable.into(),
    }
}

// ---------------------------------------------------------------------------
// Metadata wrapper
// ---------------------------------------------------------------------------

/// Thin wrapper around `std::fs::Metadata` implementing `unftp_core::storage::Metadata`.
#[derive(Debug, Clone)]
pub struct Meta(std::fs::Metadata);

impl Metadata for Meta {
    fn len(&self) -> u64 {
        self.0.len()
    }

    fn is_dir(&self) -> bool {
        self.0.is_dir()
    }

    fn is_file(&self) -> bool {
        self.0.is_file()
    }

    fn is_symlink(&self) -> bool {
        self.0.file_type().is_symlink()
    }

    fn modified(&self) -> Result<SystemTime> {
        self.0.modified().map_err(Error::from)
    }

    fn gid(&self) -> u32 {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            self.0.gid()
        }
        #[cfg(not(unix))]
        0
    }

    fn uid(&self) -> u32 {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            self.0.uid()
        }
        #[cfg(not(unix))]
        0
    }
}

// ---------------------------------------------------------------------------
// Synthesized directory metadata (for Viewer root listing)
// ---------------------------------------------------------------------------

/// Fake `Metadata` for synthesized directories in a Viewer's root listing.
#[derive(Debug, Clone)]
pub struct SynthDirMeta;

impl Metadata for SynthDirMeta {
    fn len(&self) -> u64 {
        0
    }

    fn is_dir(&self) -> bool {
        true
    }

    fn is_file(&self) -> bool {
        false
    }

    fn is_symlink(&self) -> bool {
        false
    }

    fn modified(&self) -> Result<SystemTime> {
        Ok(SystemTime::UNIX_EPOCH)
    }

    fn gid(&self) -> u32 {
        0
    }

    fn uid(&self) -> u32 {
        0
    }
}

// ---------------------------------------------------------------------------
// Store error (append-only core)
// ---------------------------------------------------------------------------

/// Errors from `store_stream`.
#[derive(Debug)]
pub enum StoreError {
    /// Attempted to write at an offset already covered by the staging file.
    Overlap,
    /// Attempted to write past the end of the staging file (would create a gap).
    Gap,
    /// The final path already exists (no overwrite allowed).
    Finalized,
    /// An I/O error occurred.
    Io(std::io::Error),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Overlap => write!(f, "overlap: start_pos < staging size"),
            StoreError::Gap => write!(f, "gap: start_pos > staging size"),
            StoreError::Finalized => write!(f, "file already finalized (no overwrite)"),
            StoreError::Io(e) => write!(f, "io error: {e}"),
        }
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let StoreError::Io(e) = self {
            Some(e)
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// store_stream — append-only write core
// ---------------------------------------------------------------------------

/// Stream `input` to the staging file for `real_final`, enforcing the non-overlap
/// rule, then atomically rename staging → final.
///
/// Steps:
/// 1. If `real_final` already exists → `Finalized`.
/// 2. Determine staging path and its current size (0 if absent).
/// 3. Classify `start_pos` vs `existing_size`; on Overlap/Gap remove staging and return error.
/// 4. Create parent dirs; open staging in append mode.
/// 5. Stream input via `tokio::io::copy`.
/// 6. Flush then rename staging → final. Return bytes written.
pub async fn store_stream<R>(
    real_final: &Path,
    start_pos: u64,
    input: R,
) -> std::result::Result<u64, StoreError>
where
    R: tokio::io::AsyncRead + Send + Unpin,
{
    // 1. No overwrite of finalized files.
    if tokio::fs::try_exists(real_final)
        .await
        .map_err(StoreError::Io)?
    {
        return Err(StoreError::Finalized);
    }

    // 2. Determine staging path and current size.
    let staging = append::staging_path(real_final);
    let existing_size = match tokio::fs::metadata(&staging).await {
        Ok(m) => m.len(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
        Err(e) => return Err(StoreError::Io(e)),
    };

    // 3. Classify start_pos.
    match append::classify_offset(start_pos, existing_size) {
        append::OffsetVerdict::Ok => {}
        append::OffsetVerdict::Overlap => {
            let _ = tokio::fs::remove_file(&staging).await;
            return Err(StoreError::Overlap);
        }
        append::OffsetVerdict::Gap => {
            let _ = tokio::fs::remove_file(&staging).await;
            return Err(StoreError::Gap);
        }
    }

    // 4. Create parent dirs and open staging file in append+create mode.
    if let Some(parent) = staging.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(StoreError::Io)?;
    }

    let mut file = tokio::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(&staging)
        .await
        .map_err(StoreError::Io)?;

    // 5. Stream.
    let mut input = input;
    let bytes_written = tokio::io::copy(&mut input, &mut file)
        .await
        .map_err(|e| {
            // Best effort cleanup on error.
            let staging_clone = staging.clone();
            tokio::spawn(async move {
                let _ = tokio::fs::remove_file(&staging_clone).await;
            });
            StoreError::Io(e)
        })?;

    // 6. Flush and atomically rename.
    use tokio::io::AsyncWriteExt;
    file.flush().await.map_err(StoreError::Io)?;
    drop(file);
    tokio::fs::rename(&staging, real_final)
        .await
        .map_err(StoreError::Io)?;

    Ok(bytes_written)
}

// ---------------------------------------------------------------------------
// ReoBackend
// ---------------------------------------------------------------------------

/// Stateless storage backend — all per-user state lives in `ReoUser.role`.
#[derive(Debug)]
pub struct ReoBackend;

#[async_trait]
impl StorageBackend<ReoUser> for ReoBackend {
    type Metadata = Meta;

    fn supported_features(&self) -> u32 {
        // Advertise FEATURE_RESTART so libunftp will honour start_pos in put/get.
        unftp_core::storage::FEATURE_RESTART
    }

    // -----------------------------------------------------------------------
    // metadata
    // -----------------------------------------------------------------------
    async fn metadata<P: AsRef<Path> + Send + Debug>(
        &self,
        user: &ReoUser,
        path: P,
    ) -> Result<Self::Metadata> {
        if !capability_allowed(&user.role, Op::Metadata) {
            return Err(ErrorKind::PermissionDenied.into());
        }
        let view = user_view(user);
        let real = view
            .resolve(path.as_ref())
            .map_err(path_err_to_storage)?;
        let m = tokio::fs::metadata(&real).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                Error::from(ErrorKind::PermanentFileNotAvailable)
            } else {
                Error::from(e)
            }
        })?;
        Ok(Meta(m.into()))
    }

    // -----------------------------------------------------------------------
    // list
    // -----------------------------------------------------------------------
    async fn list<P: AsRef<Path> + Send + Debug>(
        &self,
        user: &ReoUser,
        path: P,
    ) -> Result<Vec<Fileinfo<PathBuf, Self::Metadata>>>
    where
        <Self as StorageBackend<ReoUser>>::Metadata: Metadata,
    {
        if !capability_allowed(&user.role, Op::List) {
            return Err(ErrorKind::PermissionDenied.into());
        }

        let virt = path.as_ref();

        // Viewer at virtual root "/" with multi-root scope → synthesize dirs.
        if let Role::Viewer { scope } = &user.role {
            let is_root = virt == Path::new("/") || virt == Path::new("");
            if is_root && scope.list_root().len() > 0 && !is_single_scope(scope) {
                let entries = scope
                    .list_root()
                    .into_iter()
                    .map(|name| Fileinfo {
                        path: PathBuf::from(&name),
                        metadata: Meta(synth_dir_meta()),
                    })
                    .collect();
                return Ok(entries);
            }
        }

        let view = user_view(user);
        let real = view
            .resolve(virt)
            .map_err(path_err_to_storage)?;

        let mut entries = Vec::new();
        let mut rd = tokio::fs::read_dir(&real).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                Error::from(ErrorKind::PermanentDirectoryNotAvailable)
            } else {
                Error::from(e)
            }
        })?;

        while let Some(entry) = rd.next_entry().await.map_err(Error::from)? {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            // Hide staging files.
            if name_str.ends_with(STAGING_SUFFIX) {
                continue;
            }
            // Hide quarantine directory.
            if name_str == QUARANTINE_DIR {
                continue;
            }

            let m = match entry.metadata().await {
                Ok(m) => m,
                Err(_) => continue, // skip unreadable entries
            };

            entries.push(Fileinfo {
                path: PathBuf::from(name),
                metadata: Meta(m),
            });
        }

        Ok(entries)
    }

    // -----------------------------------------------------------------------
    // get
    // -----------------------------------------------------------------------
    async fn get<P: AsRef<Path> + Send + Debug>(
        &self,
        user: &ReoUser,
        path: P,
        start_pos: u64,
    ) -> Result<Box<dyn tokio::io::AsyncRead + Send + Sync + Unpin>> {
        if !capability_allowed(&user.role, Op::Get) {
            return Err(ErrorKind::PermissionDenied.into());
        }
        let view = user_view(user);
        let real = view
            .resolve(path.as_ref())
            .map_err(path_err_to_storage)?;

        let mut file = tokio::fs::File::open(&real).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                Error::from(ErrorKind::PermanentFileNotAvailable)
            } else {
                Error::from(e)
            }
        })?;

        if start_pos > 0 {
            file.seek(SeekFrom::Start(start_pos))
                .await
                .map_err(Error::from)?;
        }

        Ok(Box::new(file))
    }

    // -----------------------------------------------------------------------
    // put
    // -----------------------------------------------------------------------
    async fn put<P: AsRef<Path> + Send + Debug, R: tokio::io::AsyncRead + Send + Sync + Unpin + 'static>(
        &self,
        user: &ReoUser,
        input: R,
        path: P,
        start_pos: u64,
    ) -> Result<u64> {
        if !capability_allowed(&user.role, Op::Put) {
            return Err(ErrorKind::PermissionDenied.into());
        }

        let home = match &user.role {
            Role::Uploader { home } => home.clone(),
            Role::Viewer { .. } => return Err(ErrorKind::PermissionDenied.into()),
        };

        let virt = path.as_ref();
        let filename = virt
            .file_name()
            .ok_or_else(|| Error::from(ErrorKind::FileNameNotAllowedError))?
            .to_string_lossy()
            .into_owned();

        // Quarantine path: Reolink test files.
        if append::is_reolink_test_file(&filename) {
            let quarantine_dir = home.join(QUARANTINE_DIR);
            tokio::fs::create_dir_all(&quarantine_dir)
                .await
                .map_err(Error::from)?;
            let dest = quarantine_dir.join(&filename);
            let mut file = tokio::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&dest)
                .await
                .map_err(Error::from)?;
            let mut input = input;
            let bytes = tokio::io::copy(&mut input, &mut file)
                .await
                .map_err(Error::from)?;
            return Ok(bytes);
        }

        // Normal path: resolve via scope and apply append-only store.
        let view = user_view(user);
        let real_final = view
            .resolve(virt)
            .map_err(path_err_to_storage)?;

        store_stream(&real_final, start_pos, input)
            .await
            .map_err(store_error_to_storage)
    }

    // -----------------------------------------------------------------------
    // del
    // -----------------------------------------------------------------------
    async fn del<P: AsRef<Path> + Send + Debug>(&self, _user: &ReoUser, _path: P) -> Result<()> {
        Err(ErrorKind::PermissionDenied.into())
    }

    // -----------------------------------------------------------------------
    // mkd
    // -----------------------------------------------------------------------
    async fn mkd<P: AsRef<Path> + Send + Debug>(&self, user: &ReoUser, path: P) -> Result<()> {
        if !capability_allowed(&user.role, Op::Mkd) {
            return Err(ErrorKind::PermissionDenied.into());
        }
        let view = user_view(user);
        let real = view
            .resolve(path.as_ref())
            .map_err(path_err_to_storage)?;
        tokio::fs::create_dir_all(&real)
            .await
            .map_err(Error::from)
    }

    // -----------------------------------------------------------------------
    // rename
    // -----------------------------------------------------------------------
    async fn rename<P: AsRef<Path> + Send + Debug>(
        &self,
        _user: &ReoUser,
        _from: P,
        _to: P,
    ) -> Result<()> {
        Err(ErrorKind::PermissionDenied.into())
    }

    // -----------------------------------------------------------------------
    // rmd
    // -----------------------------------------------------------------------
    async fn rmd<P: AsRef<Path> + Send + Debug>(&self, _user: &ReoUser, _path: P) -> Result<()> {
        Err(ErrorKind::PermissionDenied.into())
    }

    // -----------------------------------------------------------------------
    // cwd
    // -----------------------------------------------------------------------
    async fn cwd<P: AsRef<Path> + Send + Debug>(&self, user: &ReoUser, path: P) -> Result<()> {
        if !capability_allowed(&user.role, Op::Cwd) {
            return Err(ErrorKind::PermissionDenied.into());
        }

        let virt = path.as_ref();

        // Viewer at "/" with multi-root scope: "/" is always valid.
        if let Role::Viewer { scope } = &user.role {
            let is_root = virt == Path::new("/") || virt == Path::new("");
            if is_root && !is_single_scope(scope) {
                return Ok(());
            }
        }

        let view = user_view(user);
        let real = view
            .resolve(virt)
            .map_err(path_err_to_storage)?;

        let m = tokio::fs::metadata(&real).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                Error::from(ErrorKind::PermanentDirectoryNotAvailable)
            } else {
                Error::from(e)
            }
        })?;

        if m.is_dir() {
            Ok(())
        } else {
            Err(ErrorKind::PermanentDirectoryNotAvailable.into())
        }
    }
}

// ---------------------------------------------------------------------------
// Helper: check if a ScopeMap is single-root (no multi-camera synthesis needed)
// ---------------------------------------------------------------------------

fn is_single_scope(scope: &ScopeMap) -> bool {
    scope.list_root().is_empty()
}

// ---------------------------------------------------------------------------
// StoreError → storage Error
// ---------------------------------------------------------------------------

fn store_error_to_storage(e: StoreError) -> Error {
    match e {
        StoreError::Overlap | StoreError::Gap => {
            Error::new(ErrorKind::FileNameNotAllowedError, e.to_string())
        }
        StoreError::Finalized => Error::new(ErrorKind::PermanentFileNotAvailable, e.to_string()),
        StoreError::Io(io_err) => Error::from(io_err),
    }
}

// ---------------------------------------------------------------------------
// Synthesize a real std::fs::Metadata for a directory (used for Viewer root listing)
// We need Meta(std::fs::Metadata) but std::fs::Metadata can't be constructed
// directly — we use a real tempdir instead.
// ---------------------------------------------------------------------------

fn synth_dir_meta() -> std::fs::Metadata {
    // We need a real std::fs::Metadata for a directory. Use the current directory.
    std::fs::metadata(".").expect("cannot read current dir metadata for synthesis")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::Role;
    use crate::paths::ScopeMap;
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use tempfile::tempdir;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn uploader(home: PathBuf) -> ReoUser {
        ReoUser {
            login: "cam".to_string(),
            role: Role::Uploader { home },
            require_tls: false,
        }
    }

    fn viewer(scope: ScopeMap) -> ReoUser {
        ReoUser {
            login: "viewer".to_string(),
            role: Role::Viewer { scope },
            require_tls: false,
        }
    }

    // -----------------------------------------------------------------------
    // capability_allowed matrix
    // -----------------------------------------------------------------------

    #[test]
    fn uploader_allowed_ops() {
        let role = Role::Uploader { home: PathBuf::from("/tmp") };
        assert!(capability_allowed(&role, Op::Put));
        assert!(capability_allowed(&role, Op::Mkd));
        assert!(capability_allowed(&role, Op::List));
        assert!(capability_allowed(&role, Op::Metadata));
        assert!(capability_allowed(&role, Op::Cwd));
    }

    #[test]
    fn uploader_denied_ops() {
        let role = Role::Uploader { home: PathBuf::from("/tmp") };
        assert!(!capability_allowed(&role, Op::Get));
        assert!(!capability_allowed(&role, Op::Del));
        assert!(!capability_allowed(&role, Op::Rmd));
        assert!(!capability_allowed(&role, Op::Rename));
    }

    #[test]
    fn viewer_allowed_ops() {
        let scope = ScopeMap::single(PathBuf::from("/tmp"));
        let role = Role::Viewer { scope };
        assert!(capability_allowed(&role, Op::Get));
        assert!(capability_allowed(&role, Op::List));
        assert!(capability_allowed(&role, Op::Metadata));
        assert!(capability_allowed(&role, Op::Cwd));
    }

    #[test]
    fn viewer_denied_ops() {
        let scope = ScopeMap::single(PathBuf::from("/tmp"));
        let role = Role::Viewer { scope };
        assert!(!capability_allowed(&role, Op::Put));
        assert!(!capability_allowed(&role, Op::Mkd));
        assert!(!capability_allowed(&role, Op::Del));
        assert!(!capability_allowed(&role, Op::Rmd));
        assert!(!capability_allowed(&role, Op::Rename));
    }

    // -----------------------------------------------------------------------
    // user_view
    // -----------------------------------------------------------------------

    #[test]
    fn user_view_uploader_maps_to_single() {
        let dir = tempdir().unwrap();
        let home = dir.path().to_path_buf();
        let u = uploader(home.clone());
        let view = user_view(&u);
        // single-root scope: list_root() returns empty (no multi-root names).
        assert!(view.list_root().is_empty());
        // Can resolve a path inside the home.
        let test_file = home.join("clip.mp4");
        std::fs::write(&test_file, b"x").unwrap();
        let resolved = view.resolve(Path::new("/clip.mp4")).unwrap();
        assert_eq!(resolved, test_file);
    }

    #[test]
    fn user_view_viewer_maps_to_scope() {
        let dir = tempdir().unwrap();
        let cam_a = dir.path().join("cam-a");
        let cam_b = dir.path().join("cam-b");
        std::fs::create_dir_all(&cam_a).unwrap();
        std::fs::create_dir_all(&cam_b).unwrap();
        let mut roots = BTreeMap::new();
        roots.insert("cam-a".to_string(), cam_a);
        roots.insert("cam-b".to_string(), cam_b);
        let scope = ScopeMap::multi(roots);
        let v = viewer(scope);
        let view = user_view(&v);
        let mut roots_listed = view.list_root();
        roots_listed.sort();
        assert_eq!(roots_listed, vec!["cam-a", "cam-b"]);
    }

    // -----------------------------------------------------------------------
    // store_stream tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn store_first_write_then_finalizes() {
        let dir = tempdir().unwrap();
        let final_path = dir.path().join("clip.mp4");
        let data = b"hello world";
        let bytes = store_stream(&final_path, 0, &data[..]).await.unwrap();
        assert_eq!(bytes, data.len() as u64);
        assert!(final_path.exists(), "final file must exist after store_stream");
        let staging = append::staging_path(&final_path);
        assert!(!staging.exists(), "staging file must be removed after rename");
        let contents = std::fs::read(&final_path).unwrap();
        assert_eq!(contents, data);
    }

    #[tokio::test]
    async fn store_overlap_rejected_staging_discarded() {
        let dir = tempdir().unwrap();
        let final_path = dir.path().join("clip.mp4");
        // First partial write: 5 bytes.
        let first = b"hello";
        store_stream(&final_path, 0, &first[..]).await.unwrap();
        // Final now exists — remove it to simulate an aborted (no finalize) case.
        // Actually: store_stream finalizes on success. Simulate partial staging manually.
        let staging = append::staging_path(&final_path);
        // Remove the final file and recreate a staging file with 5 bytes.
        std::fs::remove_file(&final_path).unwrap();
        std::fs::write(&staging, b"hello").unwrap();
        // Now attempt overlap: start_pos=3 < existing=5.
        let err = store_stream(&final_path, 3, &b" world"[..]).await.unwrap_err();
        assert!(matches!(err, StoreError::Overlap));
        assert!(!staging.exists(), "staging must be discarded on overlap");
    }

    #[tokio::test]
    async fn store_gap_rejected_staging_discarded() {
        let dir = tempdir().unwrap();
        let final_path = dir.path().join("clip.mp4");
        let staging = append::staging_path(&final_path);
        std::fs::write(&staging, b"hello").unwrap(); // 5 bytes in staging
        // Gap: start_pos=10 > existing=5.
        let err = store_stream(&final_path, 10, &b"world"[..]).await.unwrap_err();
        assert!(matches!(err, StoreError::Gap));
        assert!(!staging.exists(), "staging must be discarded on gap");
    }

    #[tokio::test]
    async fn store_already_finalized_rejected() {
        let dir = tempdir().unwrap();
        let final_path = dir.path().join("clip.mp4");
        std::fs::write(&final_path, b"original").unwrap();
        let err = store_stream(&final_path, 0, &b"new"[..]).await.unwrap_err();
        assert!(matches!(err, StoreError::Finalized));
    }

    #[tokio::test]
    async fn store_resume_extends_then_finalizes() {
        let dir = tempdir().unwrap();
        let final_path = dir.path().join("clip.mp4");
        let staging = append::staging_path(&final_path);
        // Simulate a partial upload: staging has first 5 bytes.
        std::fs::write(&staging, b"hello").unwrap();
        // Resume at offset 5.
        let bytes = store_stream(&final_path, 5, &b" world"[..]).await.unwrap();
        assert_eq!(bytes, 6);
        let contents = std::fs::read(&final_path).unwrap();
        assert_eq!(contents, b"hello world");
        assert!(!staging.exists());
    }

    // -----------------------------------------------------------------------
    // Backend integration: list hides staging and quarantine
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn list_hides_staging_and_quarantine() {
        let dir = tempdir().unwrap();
        let home = dir.path().to_path_buf();
        // Create a real file, a staging file, and a quarantine dir.
        std::fs::write(home.join("clip.mp4"), b"data").unwrap();
        std::fs::write(
            home.join(format!("clip.mp4{}", STAGING_SUFFIX)),
            b"partial",
        )
        .unwrap();
        std::fs::create_dir(home.join(QUARANTINE_DIR)).unwrap();

        let u = uploader(home);
        let backend = ReoBackend;
        let entries = backend.list(&u, Path::new("/")).await.unwrap();
        let names: Vec<_> = entries
            .iter()
            .map(|fi| fi.path.to_string_lossy().into_owned())
            .collect();
        assert!(names.contains(&"clip.mp4".to_string()), "clip.mp4 should be visible");
        assert!(
            !names.iter().any(|n| n.ends_with(STAGING_SUFFIX)),
            "staging files must be hidden"
        );
        assert!(
            !names.contains(&QUARANTINE_DIR.to_string()),
            "quarantine dir must be hidden"
        );
    }

    // -----------------------------------------------------------------------
    // Backend: put blocks viewers
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn put_denied_for_viewer() {
        let dir = tempdir().unwrap();
        let scope = ScopeMap::single(dir.path().to_path_buf());
        let v = viewer(scope);
        let backend = ReoBackend;
        let data: &[u8] = b"data";
        let result = backend.put(&v, data, Path::new("/clip.mp4"), 0).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::PermissionDenied);
    }

    // -----------------------------------------------------------------------
    // Backend: get blocks uploaders
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn get_denied_for_uploader() {
        let dir = tempdir().unwrap();
        let u = uploader(dir.path().to_path_buf());
        let backend = ReoBackend;
        let result = backend.get(&u, Path::new("/clip.mp4"), 0).await;
        assert!(result.is_err(), "expected Err for uploader get");
        // Extract error kind without requiring T: Debug.
        let err_kind = match result {
            Err(e) => e.kind(),
            Ok(_) => panic!("expected Err"),
        };
        assert_eq!(err_kind, ErrorKind::PermissionDenied);
    }

    // -----------------------------------------------------------------------
    // Backend: del/rmd/rename always denied
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn del_always_denied() {
        let dir = tempdir().unwrap();
        let u = uploader(dir.path().to_path_buf());
        let backend = ReoBackend;
        let result = backend.del(&u, Path::new("/clip.mp4")).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    async fn rmd_always_denied() {
        let dir = tempdir().unwrap();
        let u = uploader(dir.path().to_path_buf());
        let backend = ReoBackend;
        let result = backend.rmd(&u, Path::new("/some-dir")).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    async fn rename_always_denied() {
        let dir = tempdir().unwrap();
        let u = uploader(dir.path().to_path_buf());
        let backend = ReoBackend;
        let result = backend
            .rename(&u, Path::new("/a.mp4"), Path::new("/b.mp4"))
            .await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::PermissionDenied);
    }

    // -----------------------------------------------------------------------
    // Backend: quarantine for Reolink test files
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn quarantine_reolink_test_file() {
        let dir = tempdir().unwrap();
        let home = dir.path().to_path_buf();
        let u = uploader(home.clone());
        let backend = ReoBackend;
        // First write.
        backend
            .put(&u, &b"test data"[..], Path::new("/test.txt"), 0)
            .await
            .unwrap();
        let quarantine = home.join(QUARANTINE_DIR).join("test.txt");
        assert!(quarantine.exists(), "test file must land in quarantine");
        // Second write (overwrite allowed in quarantine).
        backend
            .put(&u, &b"new data"[..], Path::new("/test.txt"), 0)
            .await
            .unwrap();
        let contents = std::fs::read(&quarantine).unwrap();
        assert_eq!(contents, b"new data", "quarantine must overwrite");
    }
}
