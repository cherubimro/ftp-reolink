//! Pure, dependency-free append-only enforcement logic.
use std::path::{Path, PathBuf};

pub const STAGING_SUFFIX: &str = ".reoftpd-partial";
pub const QUARANTINE_DIR: &str = ".quarantine";

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum OffsetVerdict {
    Ok,
    Overlap,
    Gap,
}

/// A store may only begin exactly at the current end of the staging file.
pub fn classify_offset(start_pos: u64, existing_size: u64) -> OffsetVerdict {
    use std::cmp::Ordering::*;
    match start_pos.cmp(&existing_size) {
        Equal => OffsetVerdict::Ok,
        Less => OffsetVerdict::Overlap,
        Greater => OffsetVerdict::Gap,
    }
}

/// Hidden staging path for an in-progress upload of `final_path`.
pub fn staging_path(final_path: &Path) -> PathBuf {
    let mut s = final_path.as_os_str().to_owned();
    s.push(STAGING_SUFFIX);
    PathBuf::from(s)
}

/// Reolink's FTP connection test uploads a probe named exactly `test`,
/// `test.<ext>` (e.g. test.txt/test.jpg), or `testftp*`. Match narrowly so a
/// real capture is never mistaken for a probe and silently quarantined.
pub fn is_reolink_test_file(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower == "test" || lower.starts_with("test.") || lower.starts_with("testftp")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn offset_equal_is_ok() {
        assert_eq!(classify_offset(100, 100), OffsetVerdict::Ok);
        assert_eq!(classify_offset(0, 0), OffsetVerdict::Ok);
    }

    #[test]
    fn offset_below_existing_is_overlap() {
        assert_eq!(classify_offset(50, 100), OffsetVerdict::Overlap);
        assert_eq!(classify_offset(0, 1), OffsetVerdict::Overlap);
    }

    #[test]
    fn offset_above_existing_is_gap() {
        assert_eq!(classify_offset(101, 100), OffsetVerdict::Gap);
    }

    #[test]
    fn staging_path_appends_suffix() {
        let p = staging_path(Path::new("/srv/reolink/cam/clip.mp4"));
        assert_eq!(p, Path::new("/srv/reolink/cam/clip.mp4.reoftpd-partial"));
    }

    #[test]
    fn detects_reolink_test_file() {
        assert!(is_reolink_test_file("test.txt"));
        assert!(is_reolink_test_file("TestFtp.dat"));
        assert!(is_reolink_test_file("test"));
        assert!(!is_reolink_test_file("testament.mp4"));
        assert!(!is_reolink_test_file("testudo.mp4"));
        assert!(!is_reolink_test_file("MD_2026-06-19_120000.mp4"));
    }
}
