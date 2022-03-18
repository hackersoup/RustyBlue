mod packet;

use std::{fmt::Display, num::TryFromIntError, time::Duration};

use clap::Parser;
use packet::protocol::*;
use pcap::{Capture, Device, Packet};

use crate::packet::{ethernet::Ethernet, ip::IP};

// Replaced with using clap args
// fn get_wifi() -> Option<Device> {
//     for interface in Device::list().unwrap() {
//         if interface.name == "eth0" {
//             return Some(interface);
//         }
//     }
//     None
// }

/// Program configuration arguments
#[derive(Debug, Parser)]
#[clap(author, version, about)]
struct Args {
    /// Interface to listen on for packets
    interface: String,
}

/// Centralize processing of Header times to avoid potential logic bugs elsewhere
struct HeaderReportedTime(Duration);

/// Create a time representation directly from a packet, no need to worry about the logic
impl TryFrom<&Packet<'_>> for HeaderReportedTime {
    type Error = TryFromIntError;

    fn try_from(packet: &Packet) -> Result<Self, Self::Error> {
        Ok(Self(
            Duration::from_secs(packet.header.ts.tv_sec.try_into()?)
                + Duration::from_micros(packet.header.ts.tv_usec.try_into()?),
        ))
    }
}

impl Display for HeaderReportedTime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{:.9}", self.0.as_secs(), self.0.subsec_micros())
    }
}

fn main() {
    let args = Args::parse();

    // Selecting device from args instead
    // let dev = get_wifi().unwrap();
    let dev = Device::list()
        .unwrap()
        .into_iter()
        .find(|d| d.name == args.interface)
        .expect("Couldn't find specified interface");

    // Removed .timeout(2500)
    // Setting a timeout and then ignoring the error inside the main working loop is counter-intuitive.
    // Just let it indefinitely block instead, clears up the logic a bit
    let mut capture = Capture::from_device(dev).unwrap().open().unwrap();

    let mut packet_count: u64 = 1; // Renamed for clarity, i is ambiguous in this case

    // let mut start_time: f64 = 0.0; // Unused code

    let mut term = term::stdout().unwrap();
    loop {
        let packet = match capture.next() {
            Ok(x) => x,
            // Dead code due to changes made above
            // Err(pcap::Error::TimeoutExpired) => continue,
            Err(_) => {
                println!("Unknown Error in getting next packet");
                continue;
            }
        };
        // We can use existing rust types to do better
        // Convert this into an addition of `Duration` structs to have precise control of time parameters
        // Also, giving a more idiomatic name than `time`, there are lots of different kinds of time in this code
        // let time: f64 = format!("{}.{}", packet.header.ts.tv_sec, packet.header.ts.tv_usec)
        //     .parse()
        //     .unwrap();
        // if packet_count == 1 {
        //     start_time = time;
        // }
        let header_reported_time = HeaderReportedTime::try_from(&packet).unwrap();

        // Removing this, its only used once so no real need to have it as a shorthand variable
        // let len = packet.header.len;

        // Only used once, removing to reduce clutter
        // let data = packet.data;

        // Clearer name
        let eth_packet = Ethernet::new(&packet.data).unwrap();

        // Unused
        // let dst_mac = &eth.dst;
        // let src_mac = &eth.src;

        // Clean up a bit
        let int = match eth_packet.ethertype {
            Layer3Protocol::Unknown => continue,
            proto => IP::new(eth_packet.payload, proto),
        }
        .unwrap();

        let dst_ip = &int.dst;
        let src_ip = &int.src;

        let protocol = &int.protocol;
        let transport_data = match protocol {
            Layer4Protocol::TCP | Layer4Protocol::UDP => {
                let transport = packet::transport::Transport::new(int.payload, protocol).unwrap();
                term.fg(transport.get_color()).unwrap();
                (transport.get_tag(), transport.to_string())
            }
            Layer4Protocol::ICMP | Layer4Protocol::ICMPv6 => {
                term.fg(term::color::BRIGHT_MAGENTA).unwrap();
                let icmp = packet::icmp::ICMP::new(int.payload, protocol).unwrap();
                (format!("{}", protocol), icmp.to_string())
            }
            Layer4Protocol::ARP => {
                term.fg(term::color::YELLOW).unwrap();
                (String::from("ARP"), int.arp.unwrap().to_string())
            }
            Layer4Protocol::Unknown => {
                term.fg(term::color::RED).unwrap();
                (String::from("???"), String::from("???"))
            }
        };
        writeln!(
            term,
            "{} | {} | {} | {} | {} | {} | {}",
            packet_count,
            header_reported_time,
            src_ip,
            dst_ip,
            transport_data.0,
            packet.header.len,
            transport_data.1
        )
        .unwrap();
        term.reset().unwrap();
        packet_count += 1;
    }
}
