use std::net::ToSocketAddrs;

use crate::{utils::join_host_port, ATTRIBUTE_FAMILY_IPV4, ATTRIBUTE_FAMILY_IPV6};

#[derive(Debug, Clone)]
pub struct Host {
    pub family: u16,
    pub ip: String,
    pub port: u16,
}

impl Host {
    pub fn new(s: &str) -> Result<Host, std::io::Error> {
        s.to_socket_addrs()
            .map_err(|e| e)?
            .next()
            .map(|addr| {
                let family = if addr.ip().is_ipv4() {
                    ATTRIBUTE_FAMILY_IPV4
                } else {
                    ATTRIBUTE_FAMILY_IPV6
                };
                Host {
                    family,
                    ip: addr.ip().to_string(),
                    port: addr.port(),
                }
            })
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "No address found"))
        // 将 None 转换为 Err
    }

    pub fn transport_addr(&self) -> String {
        join_host_port(&self.ip, &self.port.to_string())
    }

    pub fn string(&self) -> String {
        Host::transport_addr(&self)
    }
}
