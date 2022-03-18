use std::fmt;

#[derive(Debug, PartialEq)]
pub enum Layer3 {
    IPv4,
    IPv6,
    ARP,
    Unknown(u16),
}

impl fmt::Display for Layer3 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Layer3::IPv4 => write!(f, "IPv4"),
            Layer3::IPv6 => write!(f, "IPv6"),
            Layer3::ARP => write!(f, "ARP"),
            Layer3::Unknown(_) => write!(f, "???"),
        }
    }
}

impl From<u16> for Layer3 {
    fn from(n: u16) -> Self {
        match n {
            0x0800 => Self::IPv4,
            0x0806 => Self::ARP,
            0x86dd => Self::IPv6,
            unknown => Self::Unknown(unknown),
        }
    }
}

pub enum Layer4Protocol {
    TCP,
    UDP,
    ICMP,
    ICMPv6,
    ARP,
    Unknown,
}

impl fmt::Display for Layer4Protocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Layer4Protocol::TCP => write!(f, "TCP"),
            Layer4Protocol::UDP => write!(f, "UDP"),
            Layer4Protocol::ICMP => write!(f, "ICMP"),
            Layer4Protocol::ICMPv6 => write!(f, "ICMPv6"),
            Layer4Protocol::ARP => write!(f, "ARP"),
            Layer4Protocol::Unknown => write!(f, "???"),
        }
    }
}
