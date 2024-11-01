use byteorder::{BigEndian, ByteOrder};

use crate::utils::align;
use crate::{
    attribute, host, Host, ATTRIBUTE_CHANGED_ADDRESS, ATTRIBUTE_MAPPED_ADDRESS,
    ATTRIBUTE_OTHER_ADDRESS, ATTRIBUTE_XOR_MAPPED_ADDRESS, ATTRIBUTE_XOR_MAPPED_ADDRESS_EXP,
    MAGIC_COOKIE,
};

use super::utils;
use super::Attribute;
use rand::thread_rng;
use rand::Rng;
use std::f32::consts::E;
use std::fmt::Binary;
use std::io::{self, Read, Write};
use std::task::ready;
use std::thread::panicking;
use std::vec;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Packet {
    pub types: u16,
    pub length: u16,
    pub trans_id: [u8; 16], // 4 bytes magic cookie + 12 bytes transaction id
    pub attributes: Vec<Attribute>,
}

impl Packet {
    pub fn new() -> Packet {
        let mut trans_id = [0u8; 16];
        BigEndian::write_u32(&mut trans_id[..4], MAGIC_COOKIE);
        let mut rng = thread_rng();
        rng.fill(&mut trans_id[4..]);

        Packet {
            types: 0, // 默认类型
            length: 0,
            trans_id,
            attributes: Vec::new(),
        }
    }
    pub fn new_packet_form_bytes(packet_bytes: Vec<u8>) -> Result<Packet, String> {
        if packet_bytes.len() < 20 {
            return Err("Received data length too short".to_string());
        } else if (packet_bytes.len() - 20) > u16::MAX as usize {
            return Err("Received data length too long".to_string());
        }

        let types = BigEndian::read_u16(&packet_bytes[..2]);
        let length = BigEndian::read_u16(&packet_bytes[2..4]);
        let trans_id = packet_bytes[4..20].to_vec();
        let mut attributes: Vec<Attribute> = Vec::with_capacity(10);
        let packet_bytes = packet_bytes[20..].to_vec();

        let mut i = 4;
        while i < packet_bytes.len() {
            let p_types = BigEndian::read_u16(&packet_bytes[i..i + 2]);
            let p_length = BigEndian::read_u16(&packet_bytes[i + 2..i + 4]);
            let end = i as u16 + 4 + p_length;
            if end < i as u16 + 4 || end > packet_bytes.len() as u16 {
                return Err("Received data format mismatch".to_string());
            }
            let value = packet_bytes[i + 4..end as usize].to_vec();
            // let attribute = Attribute::new(p_types,&value);
            attributes.push(Attribute::new(p_types, &value));
            i = (utils::align(p_length) + 4) as usize;
        }

        Ok(Packet {
            types,
            length,
            trans_id: utils::convert_vec_to_u8_array(&trans_id),
            attributes,
        })
    }

    pub fn add_attribute(&mut self, a: Attribute) {
        self.length += utils::align(a.length) + 4;
        self.attributes.push(a);
    }

    pub fn bytes(&self) -> Vec<u8> {
        let mut packet_bytes = vec![0u8; 4];
        BigEndian::write_u16(&mut packet_bytes[..2], self.types);
        BigEndian::write_u16(&mut packet_bytes[2..4], self.length);
        packet_bytes.extend(self.trans_id.clone());

        for a in self.attributes.clone() {
            let mut buf = vec![0u8; 2];
            BigEndian::write_u16(&mut buf, a.s_type);
            packet_bytes.extend(buf.clone());
            BigEndian::write_u16(&mut buf, a.length);
            packet_bytes.extend(buf.clone());
            packet_bytes.extend(a.value);
        }

        packet_bytes
    }

    pub fn get_raw_addr(&self, attribute: u16) -> Option<Host> {
        for mut a in self.attributes.clone() {
            if a.s_type == attribute {
                return Some(a.raw_addr());
            }
        }
        None
    }

    //  pub fn get_xor_Mapped_addr(&self) -> Option<Host> {
    //       self.get_Xor_addr(ATTRIBUTE_XOR_MAPPED_ADDRESS)
    //  }

    pub fn get_xor_addr(&self, attribute: u16) -> Option<Host> {
        for a in self.attributes.clone() {
            if a.s_type == attribute {
                return Some(a.get_xor_addr(self.trans_id.to_vec()));
            }
        }
        None
    }

    pub fn get_xor_mapped_addr(&self) -> Option<Host> {
        let mut addr = self.get_xor_addr(ATTRIBUTE_MAPPED_ADDRESS);
        if let Some(_) = addr {
            addr = self.get_xor_addr(ATTRIBUTE_XOR_MAPPED_ADDRESS_EXP);
        }
        addr
    }

    pub fn get_change_addr(&self) -> Option<Host> {
        self.get_raw_addr(ATTRIBUTE_CHANGED_ADDRESS)
    }

    pub fn get_other_addr(&self) -> Option<Host> {
        self.get_raw_addr(ATTRIBUTE_OTHER_ADDRESS)
    }
}
