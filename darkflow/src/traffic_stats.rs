//! `RUST_LOG=info cargo run --release --bin darkflow -- --header -f custom -o csv --export-path output.csv pcap test.pcap`
//!
//! TODO: add collaborative filtering from `lowptor`
//!
use std::sync::atomic::{AtomicU64, Ordering};

use crate::{packet_features::PacketFeatures, Flow};

pub const LARGE_FLOW_PACKET_THRESHOLD: u64 = 1000;

#[derive(Debug, Default)]
pub struct TrafficStats {
    total_packets: AtomicU64,
    total_wire_len: AtomicU64,
    total_flows: AtomicU64,

    large_flow_count: AtomicU64,
    large_flow_total_packets: AtomicU64,
    large_flow_total_wire_len: AtomicU64,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct TrafficStatsSnapshot {
    pub total_packets: u64,
    pub total_wire_len: u64,
    pub total_flows: u64,

    pub large_flow_count: u64,
    pub large_flow_total_packets: u64,
    pub large_flow_total_wire_len: u64,
}

impl TrafficStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_packet(&self, packet: &PacketFeatures) {
        self.total_packets.fetch_add(1, Ordering::Relaxed);
        self.total_wire_len
            .fetch_add(packet.length as u64, Ordering::Relaxed);
    }

    pub fn record_new_flow(&self) {
        self.total_flows.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_completed_flow<T: Flow>(&self, flow: &T) {
        let packet_count = flow.get_packet_count();
        if !flow.is_tcp() || packet_count > LARGE_FLOW_PACKET_THRESHOLD {
            self.large_flow_count.fetch_add(1, Ordering::Relaxed);
            self.large_flow_total_packets
                .fetch_add(packet_count, Ordering::Relaxed);
            self.large_flow_total_wire_len
                .fetch_add(flow.get_wire_len(), Ordering::Relaxed);
        }
    }

    pub fn snapshot(&self) -> TrafficStatsSnapshot {
        TrafficStatsSnapshot {
            total_packets: self.total_packets.load(Ordering::Relaxed),
            total_wire_len: self.total_wire_len.load(Ordering::Relaxed),
            total_flows: self.total_flows.load(Ordering::Relaxed),

            large_flow_count: self.large_flow_count.load(Ordering::Relaxed),
            large_flow_total_packets: self.large_flow_total_packets.load(Ordering::Relaxed),
            large_flow_total_wire_len: self.large_flow_total_wire_len.load(Ordering::Relaxed),
        }
    }
}
