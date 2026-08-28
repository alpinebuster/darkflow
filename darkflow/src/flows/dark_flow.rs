use std::net::IpAddr;

use crate::packet_features::PacketFeatures;

use super::{
    basic_flow::BasicFlow,
    features::{packet_sequence::PacketSequence, util::FlowFeature},
    flow::Flow,
    util::FlowExpireCause,
};

/// Represents the multi-flow behavior of Tor.
#[derive(Clone)]
pub struct Darkflow {
    /// Choose here for an existing flow type or leave the basic flow.
    pub basic_flow: BasicFlow,
    /// The additional features.
    pub packet_seq: PacketSequence,
}

impl Flow for Darkflow {
    fn new(
        flow_key: String,
        ipv4_source: IpAddr,
        port_source: u16,
        ipv4_destination: IpAddr,
        port_destination: u16,
        protocol: u8,
        timestamp_us: i64,
    ) -> Self {
        Darkflow {
            basic_flow: BasicFlow::new(
                flow_key,
                ipv4_source,
                port_source,
                ipv4_destination,
                port_destination,
                protocol,
                timestamp_us,
            ),
            // The initialization of the additional features.
            packet_seq: PacketSequence::new(),
        }
    }

    fn update_flow(&mut self, packet: &PacketFeatures, fwd: bool) -> bool {
        // Update the basic flow and returns true if the flow is terminated.
        let last_timestamp_us = self.basic_flow.last_timestamp_us;
        let is_terminated = self.basic_flow.update_flow(packet, fwd);

        // The update of the additional features.
        self.packet_seq.update(packet, fwd, last_timestamp_us);

        // Return the termination status of the flow.
        is_terminated
    }

    fn close_flow(&mut self, timestamp_us: i64, cause: FlowExpireCause) {
        self.basic_flow.close_flow(timestamp_us, cause);

        // The close of the customized darkflow.
        self.packet_seq.close(timestamp_us, cause);
    }

    fn dump(&self) -> String {
        // The dump of the customized darkflow.
        format!(
            "{},{},{},{},{},{},{},{},{}",
            // Basic Info
            self.basic_flow.flow_key,
            self.basic_flow.ip_source,
            self.basic_flow.port_source,
            self.basic_flow.ip_destination,
            self.basic_flow.port_destination,
            self.basic_flow.protocol,
            self.basic_flow.get_first_timestamp(),
            self.basic_flow.get_flow_duration_usec(),
            // Darkflow Info
            self.packet_seq.dump(),
        )
    }

    fn get_features() -> String {
        // The features of the customized darkflow.
        format!(
            "flow_key,ip_source,port_source,ip_destination,port_destination,\
            protocol,first_timestamp,flow_duration_usec,{}",
            PacketSequence::headers()
        )
    }

    fn dump_without_contamination(&self) -> String {
        // The dump of the customized darkflow without contaminant features.
        format!(
            "{}", self.packet_seq.dump()
        )
    }

    fn get_features_without_contamination() -> String {
        // The features of the customized darkflow without contaminant features.
        PacketSequence::headers()
    }

    fn get_first_timestamp_us(&self) -> i64 {
        self.basic_flow.first_timestamp_us
    }

    fn is_expired(
        &self,
        timestamp_us: i64,
        active_timeout: u64,
        idle_timeout: u64,
    ) -> (bool, FlowExpireCause) {
        self.basic_flow
            .is_expired(timestamp_us, active_timeout, idle_timeout)
    }

    fn is_tcp(&self) -> bool {
        self.basic_flow.is_tcp()
    }

    fn get_packet_count(&self) -> u64 {
        self.basic_flow.get_packet_count()
    }

    fn get_wire_len(&self) -> u64 {
        self.basic_flow.get_wire_len()
    }
}
