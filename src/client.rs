use std::io;
use std::io::Result;
use std::net::{ToSocketAddrs, UdpSocket};
use std::sync::Arc;

use crate::DEFAULT_SERVER_ADDR;

use super::Host;
use super::NAT;

pub struct Client {
    pub server_addr: String,
    pub local_ip: String,
    pub local_port: u16, // Rust 中端口号通常是 u16 类型
    pub software_name: String,
    pub conn: Arc<UdpSocket>, // 使用 Arc 来允许多个线程间共享 socket
}

impl Client {
    pub fn new(
        server_addr: String,
        local_ip: String,
        local_port: u16,
        software_name: String,
    ) -> std::io::Result<Client> {
        let address = format!("{}:{}", local_ip, local_port).to_string();

        let socket = UdpSocket::bind(&address)?;

        Ok(Client {
            server_addr,
            local_ip,
            local_port,
            software_name,
            conn: Arc::new(socket),
        })
    }

    pub fn discover(&mut self) -> Result<(NAT, Host)> {
        if self.server_addr.is_empty() {
            self.server_addr = DEFAULT_SERVER_ADDR.to_string();
        }

        let server_udp_addr = self
            .server_addr
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "No address found"))?;

        let socket = UdpSocket::bind(server_udp_addr)?;

        let mut conn = Arc::clone(&self.conn);

        let nat = NAT::NATBlocked;
        let host = Host {
            family: 1,
            ip: String::from("value"),
            port: 11,
        };
        Ok((nat, host))
    }
}
