use std::net::{IpAddr, Ipv4Addr};

use super::ethernet::MacAddr;

pub struct ARP {
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_mac: MacAddr,
    dst_mac: MacAddr,
    opcode: u16,
}

impl ARP {
    pub fn new(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, data: &[u8]) -> Option<ARP> {
        Some(ARP {
            src_ip,
            dst_ip,
            // src_mac: format!(
            //     "{:02X?}:{:02X?}:{:02X?}:{:02X?}:{:02X?}:{:02X?}",
            //     data[8], data[9], data[10], data[11], data[12], data[13]
            // ),
            // dst_mac: format!(
            //     "{:02X?}:{:02X?}:{:02X?}:{:02X?}:{:02X?}:{:02X?}",
            //     data[18], data[19], data[20], data[21], data[22], data[23]
            // ),
            src_mac: MacAddr::from(&data[8..14]),
            dst_mac: MacAddr::from(&data[18..24]),
            opcode: ((data[6] as u16) << 8) | data[7] as u16,
        })
    }

    pub fn to_string(&self) -> String {
        match self.opcode {
            1 => format!("Who has {}? Tell {}", self.dst_ip, self.src_ip),
            2 => format!("{} is at {}", self.src_ip, self.src_mac),
            _ => String::from("ARP"),
        }
    }
}
