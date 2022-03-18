use std::{fmt::Display, io};

use super::protocol::*;

/// Represent a MAC address.
/// Moves MAC processing logic from functions USING this, to
/// internal code so they do not have to worry about it.
pub(crate) struct MacAddr([u8; 6]);

impl Display for MacAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Outsourcing the MAC display logic to here
        write!(
            f,
            "{:02X?}:{:02X?}:{:02X?}:{:02X?}:{:02X?}:{:02X?}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5],
        )
    }
}

// Outsource the MAC Address creation logic to here
// Also give it the ability to clone the array bytes from the
// source to clean up some lifetime stuffs
impl From<&[u8]> for MacAddr {
    fn from(data: &[u8]) -> Self {
        let mut mac_bytes = [0u8; 6];
        mac_bytes.clone_from_slice(&data[0..6]);
        Self(mac_bytes)
    }
}

pub(crate) const ETHER_FRAME_MIN_SIZE: usize = 18;
pub(crate) const ETHER_FRAME_DOT1Q_OFFSET: usize = 12;

pub(crate) struct Ethernet<'a> {
    pub dst: MacAddr,
    pub src: MacAddr,
    pub dot1q_tag: u32,
    pub ethertype: Layer3,
    pub payload: &'a [u8],
}

impl TryFrom<&[u8]> for Ethernet<'_> {
    type Error = io::Error;

    /// Try to read an Ethernet packet from bytes
    ///
    /// ## Errors
    /// * [`std::io::ErrorKind::UnexpectedEof`] - If input data array too short
    fn try_from(packet_bytes: &[u8]) -> Result<Self, Self::Error> {
        if packet_bytes.len() < ETHER_FRAME_MIN_SIZE {
            return Err(Self::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Not enough bytes to construct Ethernet packet",
            ));
        }
        Ok(Self {
            dst: MacAddr::from(&packet_bytes[0..6]),
            src: MacAddr::from(&packet_bytes[6..12]),
            // Is the dot1q tag big or little endian? Idk, if I'm wrong just change it
            dot1q_tag: u32::from_be_bytes(
                packet_bytes[12..16]
                    .try_into()
                    .map_err(|_| io::ErrorKind::UnexpectedEof)?,
            ),
            ethertype: Layer3::from(u16::from_be_bytes(
                packet_bytes[16..18]
                    .try_into()
                    .map_err(|_| io::ErrorKind::UnexpectedEof)?,
            )),
            payload: &packet_bytes[18..],
        })
    }
}
