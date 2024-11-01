use crate::ATTRIBUTE_FINGERPRINT;
use crate::FINGERPRINT;
use crate::{ ATTRIBUTE_CHANGE_REQUEST, ATTRIBUTE_FAMILY_IPV4, ATTRIBUTE_SOFTWARE};
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

use super::utils;
use super::Host;
use super::Packet;
extern crate crc32fast;
use byteorder::{BigEndian, ByteOrder};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Attribute {
    pub s_type: u16,
    pub length: u16,
    pub value: Vec<u8>,
}

impl Attribute {
    pub fn new(s_type: u16, value: &[u8]) -> Self {
        let padded_value = utils::padding(&value);
        Attribute {
            s_type,
            length: padded_value.len() as u16,
            value: padded_value,
        }
    }
    pub fn new_software_attribute(name: &str) -> Attribute {
        Attribute::new(ATTRIBUTE_SOFTWARE, name.as_bytes())
    }

    pub fn new_fingerprint_attribute(pkt: &Packet) -> Attribute {
        let crc = crc32fast::hash(&pkt.bytes());
        let crc = crc ^ FINGERPRINT;
        let mut buf = vec![0u8; 4];
        BigEndian::write_u32(&mut buf, crc);
        Attribute::new(ATTRIBUTE_FINGERPRINT, &buf)
    }

    pub fn new_change_req_attribute(changeip: bool, change_port: bool) -> Attribute {
        let mut value = vec![0u8; 4];

        if changeip {
            value[3] |= 0x04
        };

        if change_port {
            value[3] |= 0x02
        }

        Attribute::new(ATTRIBUTE_CHANGE_REQUEST, &value)
    }

    //      0                   1                   2                   3
    //      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //     |x x x x x x x x|    Family     |         X-Port                |
    //     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //     |                X-Address (Variable)
    //     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    pub fn get_xor_addr(&self, trans_id: Vec<u8>) -> Host {
        let mut xor_ip = vec![0u8, 16];
        for i in 0..self.value.len() - 4 {
            xor_ip[i] = self.value[i + 4] ^ trans_id[i]
        }
        let family = self.value[1] as u16;
        let port = ((self.value[2] as u16) << 8) | (self.value[3] as u16);

        if family == ATTRIBUTE_FAMILY_IPV4 {
            xor_ip = xor_ip[0..4].to_vec()
        }

        let x = ((trans_id[2] as u16) << 8) | (trans_id[3] as u16);
        Host {
            family,
            ip: format!(
                "{}",
                Ipv4Addr::new(xor_ip[0], xor_ip[1], xor_ip[2], xor_ip[3])
            ),
            port: port ^ x,
        }
    }

    pub fn raw_addr(&mut self) -> Host {
        let family = self.value[1] as u16;
        let port = ((self.value[2] as u16) << 8) | (self.value[3] as u16);

        let ip = if family == ATTRIBUTE_FAMILY_IPV4 {
            self.value = self.value[..8].to_vec();
            format!(
                "{}.{}.{}.{}",
                self.value[4], self.value[5], self.value[6], self.value[7]
            )
        } else {
            Ipv6Addr::from(convert_vec_to_u8_array(&self.value)).to_string()
        };

        Host { family, port, ip }
    }
}

fn convert_vec_to_u8_array(vec: &Vec<u8>) -> [u8; 16] {
    let mut arry: [u8; 16] = [0; 16];

    for i in 0..vec.len().min(16) {
        arry[i] = vec[i];
    }
    arry
}

#[cfg(test)]
mod tests {

    use std::fmt;

    use super::*;

    #[test]
    fn soft_name_test() {
        let result = Attribute::new_software_attribute("版本2");
        print!("{:?}", result)
    }

    #[test]
    fn change_req_test() {
        let result = Attribute::new_change_req_attribute(true, true);
        print!("{:?}", result)
    }

    #[test]
    fn test_raw_addr_ipv6() {
        let mut my_struct = Attribute {
            s_type: 1,
            length: 1,
            value: vec![0, 10, 0, 1, 0xdb, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        };

        let result = my_struct.raw_addr();
        println!("{:?}", result.ip)
    }
}
