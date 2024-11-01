use crate::{Client, Host, Response};
use std::net::{SocketAddr, UdpSocket};

impl Client {
    fn send_with_log(
        &self,
        conn: &UdpSocket,
        addr: SocketAddr,
        change_ip: bool,
        change_port: bool,
    ) -> Result<Response, String> {
        let resp = match self.send_bind_req(conn, addr, change_ip, change_port) {
            Ok(resp) => resp,
            Err(e) => {
                if !change_ip && !change_port {
                    return Err("NAT BLOCKED".to_string());
                }
                return Err(e);
            }
        };

        if let Some(h) = resp.server_addr.clone() {
            if !addr_compare(h, addr, change_ip, change_port) {
                return Err("Server error: response IP/port".to_string());
            }
        }
        Ok(resp)
    }

    pub fn test(&self, conn: &UdpSocket, addr: SocketAddr) -> Result<Response, String> {
        self.send_with_log(conn, addr, false, false)
    }

    pub fn test_change_port(&self, conn: &UdpSocket, addr: SocketAddr) -> Result<Response, String> {
        self.send_with_log(conn, addr, false, true)
    }

    pub fn test_change_both(&self, conn: &UdpSocket, addr: SocketAddr) -> Result<Response, String> {
        self.send_with_log(conn, addr, true, true)
    }

    pub fn test1(&self, conn: &UdpSocket, addr: SocketAddr) -> Result<Response, String> {
        self.send_bind_req(conn, addr, false, false)
    }

    pub fn test2(&self, conn: &UdpSocket, addr: SocketAddr) -> Result<Response, String> {
        self.send_bind_req(conn, addr, true, true)
    }

    pub fn test3(&self, conn: &UdpSocket, addr: SocketAddr) -> Result<Response, String> {
        self.send_bind_req(conn, addr, false, true)
    }
}

fn addr_compare(host: Host, addr: SocketAddr, change_ip: bool, change_port: bool) -> bool {
    let is_ip_change = host.ip != addr.ip().to_string();
    let is_port_change = host.port != addr.port();
    return is_ip_change == change_ip && is_port_change == change_port;
}
