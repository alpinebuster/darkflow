use std::net::IpAddr;

use crate::packet_features::PacketFeatures;

use super::{
    basic_flow::BasicFlow,
    features::{packet_sequence::PacketSequence, util::FlowFeature},
    flow::Flow,
    util::FlowExpireCause,
};

/*
Multivariate Time Series (MTS) classification traffic features.

References:
    [1] Fauvel, Kevin, Fuxing Chen, and Dario Rossi.
    "A lightweight, efficient and explainable-by-design convolutional neural network for
    internet traffic classification." Proceedings of the 29th ACM SIGKDD Conference on
    Knowledge Discovery and Data Mining. 2023.

Examples:
    Imagine you have a dataset with n_samples = 3 and n_packets = 4.
    A sample in X_train might look like this before processing:

    X_train = [[10, -20, 30, -40],
                [-5, 15, -25, 35],
                [100, -200, 300, -400]]

    Step 1: Absolute Values (X1):
    X1 = [[10, 20, 30, 40],
            [5, 15, 25, 35],
            [100, 200, 300, 400]]

    Step 2: Signs (X2):
    X2 = [[1, -1, 1, -1],
            [-1, 1, -1, 1],
            [1, -1, 1, -1]]

    Step 3: Concatenation (X3):
    X3 = [[10, 20, 30, 40, 1, -1, 1, -1],
            [5, 15, 25, 35, -1, 1, -1, 1],
            [100, 200, 300, 400, 1, -1, 1, -1]]

    Step 4: Reshaping:
    X_train_reshaped = [[[[10, 1], [20, -1], [30, 1], [40, -1]]],
                        [[[5, -1], [15, 1], [25, -1], [35, 1]]],
                        [[[100, 1], [200, -1], [300, 1], [400, -1]]]]
*/

#[derive(Clone)]
pub struct Lexnetflow {
    /// Choose here for an existing flow type or leave the basic flow.
    pub basic_flow: BasicFlow,
    /// The additional features.
    pub packet_seq: PacketSequence,
}

impl Flow for Lexnetflow {
    fn new(
        flow_key: String,
        ipv4_source: IpAddr,
        port_source: u16,
        ipv4_destination: IpAddr,
        port_destination: u16,
        protocol: u8,
        timestamp_us: i64,
    ) -> Self {
        Lexnetflow {
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

        self.packet_seq.close(timestamp_us, cause);
    }

    fn dump(&self) -> String {
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
            // Lexnetflow Info
            self.packet_seq.dump_dir_len(),
        )
    }

    fn get_features() -> String {
        format!(
            "flow_key,ip_source,port_source,ip_destination,port_destination,\
            protocol,first_timestamp,flow_duration_usec,{}",
            PacketSequence::headers_dir_len()
        )
    }

    fn dump_without_contamination(&self) -> String {
        format!(
            "{}", self.packet_seq.dump_dir_len()
        )
    }

    fn get_features_without_contamination() -> String {
        PacketSequence::headers_dir_len()
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

    fn flow_key(&self) -> &String {
        &self.basic_flow.flow_key
    }
}
