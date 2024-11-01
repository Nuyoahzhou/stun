use crate::utils;
use std::net::SocketAddr;

use super::Host;
use super::Packet;

#[derive(Debug, Clone)]
pub struct Response {
    pub packet: Packet,             // 原始服务器数据包
    pub server_addr: Option<Host>,  // 接收数据包的地址
    pub changed_addr: Option<Host>, // 从数据包解析的地址
    pub mapped_addr: Option<Host>,  // 从数据包解析的地址，客户端 NAT 的外部地址
    pub other_addr: Option<Host>,   // 从数据包解析的地址，用于 RFC 5780 中替换 changedAddr
    pub identical: bool,            // 如果 mappedAddr 在本地地址列表中
}

impl Response {
    pub fn new(packet: Packet, conn: &SocketAddr) -> Self {
        let mut resp = Response {
            packet: packet,
            server_addr: None,
            changed_addr: None,
            mapped_addr: None,
            other_addr: None,
            identical: false,
        };

        let mapped_addr = resp.packet.get_xor_mapped_addr();
        resp.mapped_addr = if let Some(mapped_addr) = mapped_addr {
            Some(mapped_addr)
        } else {
            resp.packet.get_xor_mapped_addr()
        };

        let local_addr_str = conn.ip().to_string();
        if let Some(addr) = resp.mapped_addr.clone() {
            let mapped_addr_str = addr.string();
            resp.identical = utils::is_local_addrss(&local_addr_str, &mapped_addr_str)
        }

        if let Some(addr) = resp.packet.get_change_addr() {
            let change_addr_host = Host::new(&addr.string());
            match change_addr_host {
                Ok(h) => resp.changed_addr = Some(h),
                Err(_) => resp.changed_addr = None,
            }
        }

        if let Some(addr) = resp.packet.get_other_addr() {
            let addr_host = Host::new(&addr.string());
            match addr_host {
                Ok(h) => resp.other_addr = Some(h),
                Err(_) => resp.other_addr = None,
            }
        }

        resp
    }
}
