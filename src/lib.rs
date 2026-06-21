#![forbid(unsafe_code)]

pub mod append;
pub mod paths;
pub mod hashing;
pub mod config;
pub mod account;
pub mod limits;
pub mod retention;
pub mod auth;

#[cfg(test)]
mod tests {
    #[test]
    fn harness_runs() {
        assert_eq!(2 + 2, 4);
    }
}
