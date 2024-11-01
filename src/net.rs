use std::io;
use std::net::UdpSocket;

use crate::Attribute;
use crate::Host;
use crate::Packet;
use crate::TYPE_BINDING_REQUEST;
use std::time::{Duration, Instant};

use super::Client;
use super::Response;

const NUM_RETRANSMIT: usize = 9;
const DEFAULT_TIMEOUT: u64 = 100;
const MAX_TIMEOUT: u64 = 1600;
const MAX_PACKET_SIZE: usize = 1024;

impl Client {
    pub fn send_bind_req(
        &self,
        conn: &UdpSocket,
        addr: std::net::SocketAddr,
        change_ip: bool,
        change_port: bool,
    ) -> Result<Response, String> {
        let mut pkt = Packet::new();
        pkt.types = TYPE_BINDING_REQUEST;
        let mut attribute = Attribute::new_software_attribute(&self.software_name);
        pkt.add_attribute(attribute.clone());
        if change_ip || change_port {
            attribute = Attribute::new_change_req_attribute(change_ip, change_port);
            pkt.add_attribute(attribute.clone());
        }

        pkt.length += 8;
        attribute = Attribute::new_fingerprint_attribute(&pkt);
        pkt.length -= 8;
        pkt.add_attribute(attribute.clone());

        match self.send(pkt, conn, addr) {
            Ok(res) => return Ok(res),
            Err(e) => return Err(e.to_string()),
        };
    }

    fn send(
        &self,
        pkt: Packet,
        conn: &UdpSocket,
        addr: std::net::SocketAddr,
    ) -> Result<Response, io::Error> {
        let mut timeout = DEFAULT_TIMEOUT;

        let mut packet_bytes = vec![0u8; MAX_PACKET_SIZE];

        for _ in 0..NUM_RETRANSMIT {
            let length = conn.send_to(&pkt.bytes(), addr.clone())?;

            if length != pkt.bytes().len() {
                return Err(io::Error::new(io::ErrorKind::Other, "Asymmetric length"));
            }

            let deadline = Instant::now() + Duration::from_millis(timeout as u64);
            conn.set_read_timeout(Some(deadline.duration_since(Instant::now())))?;

            if timeout < MAX_TIMEOUT {
                timeout *= 2
            }
            loop {
                let (lengths, raddr) = match conn.recv_from(&mut packet_bytes) {
                    Ok(v) => v,
                    Err(e) => {
                        if e.kind() == io::ErrorKind::WouldBlock {
                            continue; // 非阻塞模式下，如果没有数据，继续循环
                        }
                        break;
                    }
                };
                let p = Packet::new_packet_form_bytes(packet_bytes[..lengths].to_vec());

                let p_pkt: Packet = match p {
                    Ok(v) => v,
                    Err(e) => {
                        return Err(io::Error::new(io::ErrorKind::Other, e));
                    }
                };

                if pkt.trans_id != p_pkt.trans_id {
                    continue;
                }
                let mut resp = Response::new(p_pkt, &raddr);
                resp.server_addr = Some(Host::new(&raddr.ip().to_string())?);
                return Ok(resp);
            }
        }

        return Err(io::Error::new(io::ErrorKind::Other, "fail"));
    }
}
