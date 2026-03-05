use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use chrono::Utc;
use common::{EbpfEventIpv4, EbpfEventIpv6};
use log::debug;
use pnet::packet::{
    icmp::IcmpPacket,
    ip::{IpNextHeaderProtocol, IpNextHeaderProtocols},
    ipv4::Ipv4Packet,
    ipv6::Ipv6Packet,
    tcp::TcpPacket,
    udp::UdpPacket,
    Packet,
};

// Define TCP flags
pub const FIN_FLAG: u8 = 0b00000001;
pub const SYN_FLAG: u8 = 0b00000010;
pub const RST_FLAG: u8 = 0b00000100;
pub const PSH_FLAG: u8 = 0b00001000;
pub const ACK_FLAG: u8 = 0b00010000;
pub const URG_FLAG: u8 = 0b00100000;
pub const ECE_FLAG: u8 = 0b01000000;
pub const CWR_FLAG: u8 = 0b10000000;

impl Default for PacketFeatures {
    fn default() -> Self {
        PacketFeatures {
            source_ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            destination_ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            source_port: 0,
            destination_port: 0,
            protocol: 0,
            timestamp_us: Utc::now().timestamp_micros(),
            fin_flag: 0,
            syn_flag: 0,
            rst_flag: 0,
            psh_flag: 0,
            ack_flag: 0,
            urg_flag: 0,
            cwr_flag: 0,
            ece_flag: 0,
            data_length: 0,
            header_length: 0,
            length: 0,
            window_size: 0,
            sequence_number: 0,
            sequence_number_ack: 0,
            icmp_type: None,
            icmp_code: None,
            flags: 0,
            ttl: 0,
            ip_df: 0,
            ip_mf: 0,
        }
    }
}

pub struct PacketFeatures {
    pub source_ip: IpAddr,
    pub destination_ip: IpAddr,
    pub source_port: u16,
    pub destination_port: u16,
    pub protocol: u8,
    pub timestamp_us: i64,
    pub fin_flag: u8,
    pub syn_flag: u8,
    pub rst_flag: u8,
    pub psh_flag: u8,
    pub ack_flag: u8,
    pub urg_flag: u8,
    pub cwr_flag: u8,
    pub ece_flag: u8,
    pub data_length: u16,
    pub header_length: u8,
    pub length: u16,
    pub window_size: u16,
    pub sequence_number: u32,
    pub sequence_number_ack: u32,
    pub icmp_type: Option<u8>,
    pub icmp_code: Option<u8>,
    pub flags: u8,

    pub ttl: u8,
    pub ip_df: u8,
    pub ip_mf: u8,
}

impl PacketFeatures {
    // Constructor to create PacketFeatures from EbpfEventIpv4
    pub fn from_ebpf_event_ipv4(event: &EbpfEventIpv4) -> Self {
        PacketFeatures {
            source_ip: IpAddr::V4(Ipv4Addr::from(event.ipv4_source.to_be())),
            destination_ip: IpAddr::V4(Ipv4Addr::from(event.ipv4_destination.to_be())),
            source_port: event.port_source,
            destination_port: event.port_destination,
            protocol: event.protocol,
            timestamp_us: chrono::Utc::now().timestamp_micros(),
            fin_flag: get_tcp_flag(event.combined_flags, FIN_FLAG),
            syn_flag: get_tcp_flag(event.combined_flags, SYN_FLAG),
            rst_flag: get_tcp_flag(event.combined_flags, RST_FLAG),
            psh_flag: get_tcp_flag(event.combined_flags, PSH_FLAG),
            ack_flag: get_tcp_flag(event.combined_flags, ACK_FLAG),
            urg_flag: get_tcp_flag(event.combined_flags, URG_FLAG),
            cwr_flag: get_tcp_flag(event.combined_flags, CWR_FLAG),
            ece_flag: get_tcp_flag(event.combined_flags, ECE_FLAG),
            data_length: event.data_length,
            header_length: event.header_length,
            length: event.length,
            window_size: event.window_size,
            sequence_number: event.sequence_number,
            sequence_number_ack: event.sequence_number_ack,
            icmp_type: if event.protocol == IpNextHeaderProtocols::Icmp.0 {
                Some(event.icmp_type)
            } else {
                None
            },
            icmp_code: if event.protocol == IpNextHeaderProtocols::Icmp.0 {
                Some(event.icmp_code)
            } else {
                None
            },
            flags: event.combined_flags,

            ttl: event.ttl,
            ip_df: (event.ip_flags >> 1) & 1,
            ip_mf: event.ip_flags & 1,
        }
    }

    // Constructor to create PacketFeatures from EbpfEventIpv6
    pub fn from_ebpf_event_ipv6(event: &EbpfEventIpv6) -> Self {
        PacketFeatures {
            source_ip: IpAddr::V6(Ipv6Addr::from(event.ipv6_source.to_be())),
            destination_ip: IpAddr::V6(Ipv6Addr::from(event.ipv6_destination.to_be())),
            source_port: event.port_source,
            destination_port: event.port_destination,
            protocol: event.protocol,
            timestamp_us: chrono::Utc::now().timestamp_micros(),
            fin_flag: get_tcp_flag(event.combined_flags, FIN_FLAG),
            syn_flag: get_tcp_flag(event.combined_flags, SYN_FLAG),
            rst_flag: get_tcp_flag(event.combined_flags, RST_FLAG),
            psh_flag: get_tcp_flag(event.combined_flags, PSH_FLAG),
            ack_flag: get_tcp_flag(event.combined_flags, ACK_FLAG),
            urg_flag: get_tcp_flag(event.combined_flags, URG_FLAG),
            cwr_flag: get_tcp_flag(event.combined_flags, CWR_FLAG),
            ece_flag: get_tcp_flag(event.combined_flags, ECE_FLAG),
            data_length: event.data_length,
            header_length: event.header_length,
            length: event.length,
            window_size: event.window_size,
            sequence_number: event.sequence_number,
            sequence_number_ack: event.sequence_number_ack,
            icmp_type: if event.protocol == IpNextHeaderProtocols::Icmpv6.0 {
                Some(event.icmp_type)
            } else {
                None
            },
            icmp_code: if event.protocol == IpNextHeaderProtocols::Icmpv6.0 {
                Some(event.icmp_code)
            } else {
                None
            },
            flags: event.combined_flags,

            ttl: event.hop_limit,
            ip_df: if event.ipv6_is_fragmented == 1 {0} else {1},
            ip_mf: event.mf,
        }
    }

    // Constructor to create PacketFeatures from an IPv4 packet
    pub fn from_ipv4_packet(packet: &Ipv4Packet, timestamp_us: i64) -> Option<Self> {
        let ttl = packet.get_ttl();
        let flags = packet.get_flags();
        // bit 0    | bit 1 | bit 2
        // ------------------------
        // Reserved | DF    | MF
        let df = ((flags & 0b010) != 0) as u8;
        let mf = ((flags & 0b001) != 0) as u8;

        extract_packet_features_transport(
            packet.get_source().into(),
            packet.get_destination().into(),
            packet.get_next_level_protocol(),
            timestamp_us,
            packet.get_total_length(),
            packet.payload(),
            ttl,
            df,
            mf,
        )
    }

    // Constructor to create PacketFeatures from an IPv6 packet
    pub fn from_ipv6_packet(packet: &Ipv6Packet, timestamp_us: i64) -> Option<Self> {
        let ttl = packet.get_hop_limit();
        let (is_fragmented, mf) = parse_ipv6_frag_flags(packet);

        extract_packet_features_transport(
            packet.get_source().into(),
            packet.get_destination().into(),
            packet.get_next_header(),
            timestamp_us,
            packet.packet().len() as u16,
            packet.payload(),
            ttl,
            if is_fragmented == 1 {0} else {1},
            mf,
        )
    }

    /// Generates a flow key based on IPs, ports, and protocol
    pub fn flow_key(&self) -> String {
        format!(
            "{}:{}-{}:{}-{}",
            self.source_ip,
            self.source_port,
            self.destination_ip,
            self.destination_port,
            self.protocol
        )
    }

    /// Generates a flow key based on IPs, ports, and protocol in the reverse direction
    pub fn flow_key_bwd(&self) -> String {
        format!(
            "{}:{}-{}:{}-{}",
            self.destination_ip,
            self.destination_port,
            self.source_ip,
            self.source_port,
            self.protocol
        )
    }

    /// Generates a biflow key
    pub fn biflow_key(&self) -> String {
        // Create tuples of (IP, port) for comparison
        let src = (&self.source_ip, self.source_port);
        let dst = (&self.destination_ip, self.destination_port);

        // Determine the correct order (src < dst)
        if src < dst {
            format!(
                "{}:{}-{}:{}-{}",
                self.source_ip,
                self.source_port,
                self.destination_ip,
                self.destination_port,
                self.protocol
            )
        } else {
            // If destination IP/port is "smaller", swap the order
            format!(
                "{}:{}-{}:{}-{}",
                self.destination_ip,
                self.destination_port,
                self.source_ip,
                self.source_port,
                self.protocol
            )
        }
    }
}

fn get_tcp_flag(value: u8, flag: u8) -> u8 {
    ((value & flag) != 0) as u8
}

fn extract_packet_features_transport(
    source_ip: IpAddr,
    destination_ip: IpAddr,
    protocol: IpNextHeaderProtocol,
    timestamp_us: i64,
    total_length: u16,
    packet: &[u8],
    ttl: u8,
    df: u8,
    mf: u8,
) -> Option<PacketFeatures> {
    match protocol {
        IpNextHeaderProtocols::Tcp => {
            let tcp_packet = TcpPacket::new(packet)?;
            Some(PacketFeatures {
                source_ip,
                destination_ip,
                source_port: tcp_packet.get_source(),
                destination_port: tcp_packet.get_destination(),
                protocol: protocol.0,
                timestamp_us,
                fin_flag: get_tcp_flag(tcp_packet.get_flags(), FIN_FLAG),
                syn_flag: get_tcp_flag(tcp_packet.get_flags(), SYN_FLAG),
                rst_flag: get_tcp_flag(tcp_packet.get_flags(), RST_FLAG),
                psh_flag: get_tcp_flag(tcp_packet.get_flags(), PSH_FLAG),
                ack_flag: get_tcp_flag(tcp_packet.get_flags(), ACK_FLAG),
                urg_flag: get_tcp_flag(tcp_packet.get_flags(), URG_FLAG),
                cwr_flag: get_tcp_flag(tcp_packet.get_flags(), CWR_FLAG),
                ece_flag: get_tcp_flag(tcp_packet.get_flags(), ECE_FLAG),
                data_length: tcp_packet.payload().len() as u16,
                header_length: (tcp_packet.get_data_offset() * 4) as u8,
                length: total_length,
                window_size: tcp_packet.get_window(),
                sequence_number: tcp_packet.get_sequence(),
                sequence_number_ack: tcp_packet.get_acknowledgement(),
                icmp_type: None,
                icmp_code: None,
                flags: tcp_packet.get_flags(),
                ttl,
                ip_df: df,
                ip_mf: mf,
            })
        }
        IpNextHeaderProtocols::Udp => {
            let udp_packet = UdpPacket::new(packet)?;
            Some(PacketFeatures {
                source_ip,
                destination_ip,
                source_port: udp_packet.get_source(),
                destination_port: udp_packet.get_destination(),
                protocol: protocol.0,
                timestamp_us,
                fin_flag: 0,
                syn_flag: 0,
                rst_flag: 0,
                psh_flag: 0,
                ack_flag: 0,
                urg_flag: 0,
                cwr_flag: 0,
                ece_flag: 0,
                data_length: udp_packet.payload().len() as u16,
                header_length: 8, // Fixed header size for UDP
                length: total_length,
                window_size: 0,         // No window size for UDP
                sequence_number: 0,     // No sequence number for UDP
                sequence_number_ack: 0, // No sequence number ACK for UDP
                icmp_type: None,
                icmp_code: None,
                flags: 0, // No flags for UDP
                ttl: 0,
                ip_df: 0,
                ip_mf: 0,
            })
        }
        IpNextHeaderProtocols::Icmp | IpNextHeaderProtocols::Icmpv6 => {
            let icmp_packet = IcmpPacket::new(packet)?;
            Some(PacketFeatures {
                source_ip,
                destination_ip,
                source_port: 0,
                destination_port: 0,
                protocol: protocol.0,
                timestamp_us,
                fin_flag: 0,
                syn_flag: 0,
                rst_flag: 0,
                psh_flag: 0,
                ack_flag: 0,
                urg_flag: 0,
                cwr_flag: 0,
                ece_flag: 0,
                data_length: icmp_packet.payload().len() as u16,
                header_length: 8, // Fixed header size for ICMP
                length: total_length,
                window_size: 0,         // No window size for ICMP
                sequence_number: 0,     // No sequence number for ICMP
                sequence_number_ack: 0, // No sequence number ACK for ICMP
                icmp_type: Some(icmp_packet.get_icmp_type().0),
                icmp_code: Some(icmp_packet.get_icmp_code().0),
                flags: 0, // No flags for ICMP
                ttl: 0,
                ip_df: 0,
                ip_mf: 0,
            })
        }
        _ => {
            debug!("Unsupported protocol in packet!");
            None
        }
    }
}

fn is_extension_header(proto: IpNextHeaderProtocol) -> bool {
    matches!(
        proto,
        IpNextHeaderProtocols::Hopopt // 0 Hop-by-Hop
        | IpNextHeaderProtocols::Ipv6Route // 43 Routing
        | IpNextHeaderProtocols::Ipv6Frag // 44 Fragment
        | IpNextHeaderProtocols::Esp // 50 ESP
        | IpNextHeaderProtocols::Ah // 51 Auth
        | IpNextHeaderProtocols::Ipv6Opts // 60 Destination Options
        | IpNextHeaderProtocols::MobilityHeader // 135 Mobility
        | IpNextHeaderProtocols::Hip // 139 HIP
        | IpNextHeaderProtocols::Shim6 // 140 Shim6
    )
}

/*
Fragment Header format (RFC 8200)
  1) M: More Fragments -≈> IPv4 MF
  2) Whether `Fragment Extension Header` exists -> DF

  NOTE: 
    a) Fragment Header -> Reserved
    b) Ordinary expansion header -> Hdr Ext Len

   0                    1                    2                    3
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Next Header  |   Reserved    |      Fragment Offset    |Res|M|
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         Identification                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
fn parse_ipv6_frag_flags(ipv6: &Ipv6Packet) -> (u8, u8) {
    let mut next_hdr = ipv6.get_next_header();
    let mut payload = ipv6.payload();
    let mut mf = 0u8;
    let mut ipv6_is_fragmented = 0u8; // DF IPv6 replacement

    // Traverse the extension header chain, with a maximum extension headers to prevent infinite loops
    const MAX_EXT_HEADERS: usize = 8; // Arbitrary safe limit
    for _ in 0..MAX_EXT_HEADERS {
        if payload.is_empty() {
            break;
        }

        // Fragment Header
        if next_hdr == IpNextHeaderProtocols::Ipv6Frag {
            if payload.len() >= 8 {
                // frag_off_and_flags = Bytes 2 to 3
                let frag_off_and_flags = u16::from_be_bytes([payload[2], payload[3]]);
                mf = if (frag_off_and_flags & 0b1) != 0 { 1 } else { 0 };
                ipv6_is_fragmented = 1;

                // Next header = Bytes 0
                next_hdr = IpNextHeaderProtocol(payload[0]);
                // Move the payload pointer and skip the Fragment Header (fixed at 8 bytes)
                payload = &payload[8..];
                continue;
            } else {
                break;
            }
        }

        // Exit without extension headers
        if !is_extension_header(next_hdr) {
            break;
        }

        // The extension Header should be at least 2 bytes (Next Header + Hdr Ext Len)*8
        // Fragment Header -> Reserved
        // Ordinary expansion header -> Hdr Ext Len
        // If it is less than 2 bytes, it indicates that the package is abnormal or has reached the end, and exit the loop directly
        if payload.len() < 2 {
            break;
        }
        let hdr_ext_len = payload[1] as usize;
        let ext_len_bytes = (hdr_ext_len + 1) * 8;
        if ext_len_bytes > payload.len() {
            break;
        }

        next_hdr = IpNextHeaderProtocol(payload[0]);
        payload = &payload[ext_len_bytes..];
    }

    (ipv6_is_fragmented, mf)
}
