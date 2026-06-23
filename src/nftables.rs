//! Generate an nftables ruleset enforcing per-source-IP and global connection
//! caps for the FTP control + passive ports. Printed for the admin to apply
//! with `nft -f -`; reoftpd never applies it itself.

use crate::config::Config;

pub fn render_nftables(cfg: &Config) -> String {
    let port = cfg.server.port;
    let plo = cfg.server.passive_ports[0];
    let phi = cfg.server.passive_ports[1];
    let per_ip = cfg.limits.max_connections_per_ip;
    let global = cfg.limits.max_connections;
    format!(
        "table inet reoftpd {{\n\
\tchain input {{\n\
\t\ttype filter hook input priority filter; policy accept;\n\
\t\t# Global cap on the FTP control port (backstop to the in-process session cap)\n\
\t\ttcp dport {port} ct state new ct count over {global} drop\n\
\t\t# Per-source-IP cap on control + passive data ports\n\
\t\ttcp dport {{ {port}, {plo}-{phi} }} ct state new meter reoftpd_perip {{ ip saddr ct count over {per_ip} }} drop\n\
\t}}\n\
}}\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse_str;

    const CFG: &str = r#"
[server]
listen = "0.0.0.0"
port = 21
passive_ports = [50000, 50100]
[archive]
root = "/srv/reolink"
retention_days = 30
[limits]
max_connections = 256
max_connections_per_ip = 8
new_conns_per_min_per_ip = 30
idle_timeout_secs = 120
min_transfer_rate_bytes_per_sec = 1024
failed_login_lockout = { max_attempts = 5, window_secs = 300, ban_secs = 900 }
"#;

    #[test]
    fn renders_ports_and_counts() {
        let cfg = parse_str(CFG).unwrap();
        let out = render_nftables(&cfg);
        assert!(out.contains("table inet reoftpd"));
        assert!(out.contains("tcp dport 21")); // control port
        assert!(out.contains("50000-50100")); // passive range
        assert!(out.contains("ct count over 8")); // per-IP cap
        assert!(out.contains("ct count over 256")); // global cap
        assert!(out.contains("ip saddr")); // keyed per source IP
    }
}
