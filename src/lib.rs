#![forbid(unsafe_code)]

pub mod account;
pub mod append;
pub mod auth;
pub mod backend;
pub mod cli;
pub mod config;
pub mod crypto;
pub mod hashing;
pub mod limits;
pub mod nftables;
pub mod paths;
pub mod presence;
pub mod retention;
pub mod server;
pub mod tls;

#[cfg(test)]
mod tests {
    #[test]
    fn harness_runs() {
        assert_eq!(2 + 2, 4);
    }
}
