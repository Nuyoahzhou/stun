use local_ip_address::list_afinet_netifas;
use std::net::SocketAddr;

pub fn padding(value: &[u8]) -> Vec<u8> {
    let len = value.len();
    let padding_needed = if len % 4 == 0 { 0 } else { 4 - len % 4 };
    let mut padded_value = Vec::with_capacity(len + padding_needed);
    padded_value.extend_from_slice(value);
    padded_value.resize(len + padding_needed, 0); // 重新大小
    padded_value
}

pub fn join_host_port(host: &str, port: &str) -> String {
    if host.contains(':') {
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", host, port)
    }
}

pub fn align(n: u16) -> u16 {
    (n + 3) & 0xfffc
}

pub fn convert_vec_to_u8_array(vec: &Vec<u8>) -> [u8; 16] {
    let mut arry: [u8; 16] = [0; 16];

    for i in 0..vec.len().min(16) {
        arry[i] = vec[i];
    }
    arry
}

pub fn is_local_addrss(local: &str, local_remote: &str) -> bool {
    let local_remote_addr = match local_remote.parse::<SocketAddr>() {
        Ok(addr) => addr.ip().to_string(),
        Err(_) => return false,
    };

    match local.parse::<SocketAddr>() {
        // Ok(addr) =>  addr.ip().to_string(),
        Ok(addr) => {
            if addr.ip().is_loopback() {
                return false;
            }

            if !addr.ip().is_unspecified() {
                return addr.ip().to_string() == local_remote_addr;
            }
        }
        Err(_) => return false,
    };

    // .....
    let network_interfaces = list_afinet_netifas();
    if let Ok(network_interfaces) = network_interfaces {
        for (_, ip) in network_interfaces.iter() {
            if &ip.to_string() == local_remote {
                return true;
            }
        }
        return false;
    } else {
        return false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paddint_test() {
        println!("{:?}", padding(&[1u8, 2u8]))
    }

    #[test]
    fn join_host_port_test() {
        println!("{:?}", join_host_port("127.0.0.1", "22"))
    }
}
