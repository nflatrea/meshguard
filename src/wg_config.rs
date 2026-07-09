//! WireGuard configuration and service exposure settings.
//!
//! This module handles additional WireGuard configuration options and
//! service exposure through the VPN tunnel.

use std::net::Ipv4Addr;

/// WireGuard configuration options that can be set via environment variables
#[derive(Debug, Clone)]
pub struct WgConfig {
    /// Additional AllowedIPs for the WireGuard interface (comma-separated CIDR notation)
    pub allowed_ips: Vec<String>,
    /// Services to expose through the VPN (format: host_port:vpn_port,host_port:vpn_port)
    pub expose_services: Vec<(u16, u16)>,
    /// Enable NAT masquerading for the tunnel interface
    pub enable_nat: bool,
    /// Additional iptables rules to apply
    pub custom_iptables_rules: Vec<String>,
}

impl Default for WgConfig {
    fn default() -> Self {
        Self {
            allowed_ips: vec!["0.0.0.0/0".to_string()], // Default: allow all traffic through tunnel
            expose_services: Vec::new(),
            enable_nat: true, // Default: enable NAT
            custom_iptables_rules: Vec::new(),
        }
    }
}

impl WgConfig {
    /// Load configuration from environment variables
    pub fn from_env() -> Self {
        let mut config = WgConfig::default();
        
        // Read allowed IPs from environment
        if let Ok(allowed) = std::env::var("MESHGUARD_ALLOWED_IPS") {
            config.allowed_ips = allowed
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
        
        // Read services to expose
        if let Ok(services) = std::env::var("MESHGUARD_EXPOSE_SERVICES") {
            config.expose_services = services
                .split(',')
                .filter_map(|s| {
                    let parts: Vec<&str> = s.trim().split(':').collect();
                    if parts.len() == 2 {
                        if let (Ok(host_port), Ok(vpn_port)) = (parts[0].parse::<u16>(), parts[1].parse::<u16>()) {
                            Some((host_port, vpn_port))
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                })
                .collect();
        }
        
        // Read NAT setting
        if let Ok(nat_str) = std::env::var("MESHGUARD_ENABLE_NAT") {
            config.enable_nat = nat_str.trim().to_lowercase() != "false"
                && nat_str.trim().to_lowercase() != "0"
                && nat_str.trim().to_lowercase() != "no";
        }
        
        // Read custom iptables rules
        if let Ok(rules) = std::env::var("MESHGUARD_IPTABLES_RULES") {
            config.custom_iptables_rules = rules
                .split(';')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
        
        config
    }
    
    /// Get the primary overlay IP for this node
    pub fn get_overlay_ip(&self) -> Ipv4Addr {
        // This would normally come from the identity, but we provide a default
        Ipv4Addr::new(10, 0, 0, 1)
    }
    
    /// Apply the configuration to the system
    pub fn apply(&self, iface: &str, overlay_ip: Ipv4Addr) -> anyhow::Result<()> {
        #[cfg(target_os = "linux")]
        {
            use std::process::Command;
            
            // Enable IP forwarding if NAT is enabled
            if self.enable_nat {
                let _ = Command::new("sysctl")
                    .arg("-w")
                    .arg("net.ipv4.ip_forward=1")
                    .status();
            }
            
            // Apply NAT masquerading if enabled
            if self.enable_nat {
                let _ = Command::new("iptables")
                    .arg("-t")
                    .arg("nat")
                    .arg("-A")
                    .arg("POSTROUTING")
                    .arg("-o")
                    .arg(iface)
                    .arg("-j")
                    .arg("MASQUERADE")
                    .status();
            }
            
            // Apply service exposure rules
            for &(host_port, vpn_port) in &self.expose_services {
                let _ = Command::new("iptables")
                    .arg("-t")
                    .arg("nat")
                    .arg("-A")
                    .arg("PREROUTING")
                    .arg("-p")
                    .arg("tcp")
                    .arg("--dport")
                    .arg(host_port.to_string())
                    .arg("-j")
                    .arg("DNAT")
                    .arg("--to-destination")
                    .arg(format!("{}:{}", overlay_ip, vpn_port))
                    .status();
            }
            
            // Apply custom iptables rules
            for rule in &self.custom_iptables_rules {
                let parts: Vec<&str> = rule.split_whitespace().collect();
                if !parts.is_empty() {
                    let _ = Command::new("iptables")
                        .args(parts)
                        .status();
                }
            }
        }
        
        Ok(())
    }
}