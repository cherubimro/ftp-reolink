//! Age-based retention sweep (runs outside the FTP path).
use crate::append::{QUARANTINE_DIR, STAGING_SUFFIX};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

#[derive(Debug, Default)]
pub struct SweepReport {
    pub deleted: Vec<PathBuf>,
    pub pruned_dirs: Vec<PathBuf>,
}

fn older_than(path: &Path, ttl: Duration, now: SystemTime) -> bool {
    if let Ok(meta) = std::fs::metadata(path) {
        if let Ok(modified) = meta.modified() {
            if let Ok(age) = now.duration_since(modified) {
                return age > ttl;
            }
        }
    }
    false
}

pub fn sweep(
    root: &Path,
    retention: Duration,
    quarantine_ttl: Duration,
    staging_ttl: Duration,
    now: SystemTime,
    dry_run: bool,
) -> std::io::Result<SweepReport> {
    let mut report = SweepReport::default();
    visit(root, retention, quarantine_ttl, staging_ttl, now, dry_run, &mut report)?;
    Ok(report)
}

fn visit(
    dir: &Path,
    retention: Duration,
    quarantine_ttl: Duration,
    staging_ttl: Duration,
    now: SystemTime,
    dry_run: bool,
    report: &mut SweepReport,
) -> std::io::Result<()> {
    let in_quarantine = dir.file_name().map(|n| n == QUARANTINE_DIR).unwrap_or(false);
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let ft = entry.file_type()?;
        if ft.is_dir() {
            visit(&path, retention, quarantine_ttl, staging_ttl, now, dry_run, report)?;
            // prune if emptied
            if std::fs::read_dir(&path)?.next().is_none() {
                report.pruned_dirs.push(path.clone());
                if !dry_run {
                    let _ = std::fs::remove_dir(&path);
                }
            }
        } else {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            let ttl = if in_quarantine {
                quarantine_ttl
            } else if name.ends_with(STAGING_SUFFIX) {
                staging_ttl
            } else {
                retention
            };
            if older_than(&path, ttl, now) {
                report.deleted.push(path.clone());
                if !dry_run {
                    std::fs::remove_file(&path)?;
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{Duration, SystemTime};

    fn set_mtime(p: &std::path::Path, age: Duration) {
        let t = SystemTime::now() - age;
        let ft = fs::File::open(p).unwrap();
        ft.set_modified(t).unwrap();
    }

    #[test]
    fn deletes_old_keeps_new() {
        let d = tempfile::tempdir().unwrap();
        let cam = d.path().join("cam/2026-01-01");
        fs::create_dir_all(&cam).unwrap();
        let old = cam.join("old.mp4");
        let new = cam.join("new.mp4");
        fs::write(&old, b"x").unwrap();
        fs::write(&new, b"y").unwrap();
        set_mtime(&old, Duration::from_secs(40 * 86400));
        set_mtime(&new, Duration::from_secs(1 * 86400));

        let r = sweep(
            d.path(),
            Duration::from_secs(30 * 86400),
            Duration::from_secs(3600),
            Duration::from_secs(3600),
            SystemTime::now(),
            false,
        ).unwrap();

        assert!(!old.exists());
        assert!(new.exists());
        assert!(r.deleted.iter().any(|p| p.ends_with("old.mp4")));
    }

    #[test]
    fn dry_run_deletes_nothing() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("old.mp4");
        fs::write(&f, b"x").unwrap();
        set_mtime(&f, Duration::from_secs(40 * 86400));
        let r = sweep(d.path(), Duration::from_secs(30*86400), Duration::from_secs(3600), Duration::from_secs(3600), SystemTime::now(), true).unwrap();
        assert!(f.exists());
        assert_eq!(r.deleted.len(), 1); // reported but not removed
    }
}
