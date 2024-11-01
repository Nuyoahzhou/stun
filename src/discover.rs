use crate::Host;
use std::net::SocketAddr;
use std::net::UdpSocket;

// Follow RFC 3489 and RFC 5389.
// Figure 2: Flow for type discovery process (from RFC 3489).
//                        +--------+
//                        |  Test  |
//                        |   I    |
//                        +--------+
//                             |
//                             |
//                             V
//                            /\              /\
//                         N /  \ Y          /  \ Y             +--------+
//          UDP     <-------/Resp\--------->/ IP \------------->|  Test  |
//          Blocked         \ ?  /          \Same/              |   II   |
//                           \  /            \? /               +--------+
//                            \/              \/                    |
//                                             | N                  |
//                                             |                    V
//                                             V                    /\
//                                         +--------+  Sym.      N /  \
//                                         |  Test  |  UDP    <---/Resp\
//                                         |   II   |  Firewall   \ ?  /
//                                         +--------+              \  /
//                                             |                    \/
//                                             V                     |Y
//                  /\                         /\                    |
//   Symmetric  N  /  \       +--------+   N  /  \                   V
//      NAT  <--- / IP \<-----|  Test  |<--- /Resp\               Open
//                \Same/      |   I    |     \ ?  /               Internet
//                 \? /       +--------+      \  /
//                  \/                         \/
//                  |Y                          |Y
//                  |                           |
//                  |                           V
//                  |                           Full
//                  |                           Cone
//                  V              /\
//              +--------+        /  \ Y
//              |  Test  |------>/Resp\---->Restricted
//              |   III  |       \ ?  /
//              +--------+        \  /
//                                 \/
//                                  |N
//                                  |       Port
//                                  +------>Restricted
use super::Client;
use super::NAT;

impl Client {
    pub fn discover(&self, conn: UdpSocket, addr: SocketAddr) -> (NAT, Result<Host, String>) {
        let resp = match self.test1(&conn, addr.clone()) {
            Ok(resp) => resp,
            Err(e) => return (NAT::NATError, Err(e)),
        };

        match resp.server_addr.clone() {
            Some(server_addr) => {
                if server_addr.ip != addr.ip().to_string() || server_addr.port != addr.port() {
                    return (
                        NAT::NATError,
                        Err("Server error: response IP/port".to_string()),
                    );
                }
            }
            None => return (NAT::NATBlocked, Err("NATBlocked".to_string())),
        }

        let changed_addr = resp.changed_addr;
        let identical = resp.identical;

        let mapped_addr = match resp.mapped_addr {
            Some(m) => m,
            None => return (NAT::NATError, Err("NAT::NATError".to_string())),
        };

        let change = match changed_addr {
            Some(addr) => addr,
            None => match resp.other_addr {
                Some(other_addr) => other_addr,
                None => {
                    return (
                        NAT::NATError,
                        Err("Server error: no changed address".to_string()),
                    )
                }
            },
        };

        let resp = self.test2(&conn, addr);
        let r = match resp.clone() {
            Ok(r) => r,
            Err(e) => return (NAT::NATError, Err(e)),
        };

        match r.server_addr {
            Some(server) => {
                if server.ip == addr.ip().to_string() || server.port == addr.port() {
                    return (
                        NAT::NATError,
                        Err("Server error: no changed address".to_string()),
                    );
                }
            }
            None => {
                return (
                    NAT::NATError,
                    Err("Server error: response IP/port".to_string()),
                )
            }
        }

        if identical {
            if let Err(_) = resp {
                return (NAT::SymmetricUDPFirewall, Ok(mapped_addr));
            }
            return (NAT::NATNone, Ok(mapped_addr));
        }

        if let Err(_) = resp {
            return (NAT::NATFull, Ok(mapped_addr));
        }
        let addr = change.string().parse::<SocketAddr>().unwrap();

        let resp = self.test1(&conn, addr.clone());

        if let Err(_) = resp {}

        let r = match resp {
            Ok(r) => r,
            Err(_) => return (NAT::NATUnknown, Ok(mapped_addr)),
        };

        let m_addr = match r.mapped_addr {
            Some(m) => m,
            None => {
                return (
                    NAT::NATError,
                    Err("Server error: no changed address".to_string()),
                )
            }
        };

        if m_addr.ip != addr.ip().to_string() || m_addr.port != addr.port() {
            return (
                NAT::NATError,
                Err("Server error: response IP/port".to_string()),
            );
        }

        if mapped_addr.ip == m_addr.ip && mapped_addr.port == mapped_addr.port {
            let resp = self.test3(&conn, addr.clone());

            let r = match resp {
                Ok(r) => r,
                Err(_) => {
                    return (
                        NAT::NATError,
                        Err("Server error: response IP/port".to_string()),
                    )
                }
            };

            let s_addr = match r.server_addr {
                Some(s) => s,
                None => {
                    return (NAT::NATPortRestricted, Ok(mapped_addr));
                }
            };

            if s_addr.ip != addr.ip().to_string() || s_addr.port == addr.port() {
                return (NAT::NATError, Ok(mapped_addr));
            }

            return (NAT::NATRestricted, Ok(mapped_addr));
        }

        return (NAT::NATSymetric, Ok(mapped_addr));
    }
}
