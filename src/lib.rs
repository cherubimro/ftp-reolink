#![forbid(unsafe_code)]

pub mod append;
pub mod paths;
pub mod hashing;
pub mod config;
pub mod account;
pub mod limits;
pub mod retention;
pub mod auth;
pub mod backend;
pub mod tls;
pub mod server;
pub mod cli;

#[cfg(test)]
mod tests {
    #[test]
    fn harness_runs() {
        assert_eq!(2 + 2, 4);
    }
}
