use crate::{flows::util::FlowExpireCause, packet_features::PacketFeatures};
use super::util::{FlowFeature};

#[derive(Clone)]
pub struct PacketSequence {
    dirs: Vec<i32>,        // Direction (/ -)
    lens: Vec<i32>,
    timestamps: Vec<i64>,  // Relative time us
    first_ts: Option<i64>,

    // ===== TCP flags =====
    window: Vec<u16>,

    /*
     | Flag| Binary | Function / Purpose        | Common Usage / Scenario                                                  |
     | --- | ------ | ------------------------- | ------------------------------------------------------------------------ |
     | FIN | 0x01   | Close connection          | Very important, indicates flow end                                       |
     | SYN | 0x02   | Establish connection      | Very important, distinguishes new flows                                  |
     | RST | 0x04   | Reset connection          | Important, detects errors / failed connections                           |
     | PSH | 0x08   | Push data                 | Less common, indicates application layer data should be sent immediately |
     | ACK | 0x10   | Acknowledgment valid      | Extremely common, present in almost every packet                         |
     | URG | 0x20   | Urgent pointer            | Rarely used                                                              |
     | ECE | 0x40   | ECN Echo                  | Rarely used, network congestion flag                                     |
     | CWR | 0x80   | Congestion Window Reduced | Rarely used, usually with ECN                                            |
     */
    fin: Vec<u8>,
    syn: Vec<u8>,
    rst: Vec<u8>,
    psh: Vec<u8>,
    ack: Vec<u8>,
    urg: Vec<u8>, // Rarely used
    cwr: Vec<u8>, // Rarely used
    ece: Vec<u8>, // Rarely used

    // ===== IP =====
    ttl: Vec<u8>,
    ip_df: Vec<u8>,
    ip_mf: Vec<u8>,
}

impl PacketSequence {
    pub fn new() -> Self {
        Self {
            dirs: Vec::new(),
            lens: Vec::new(),
            timestamps: Vec::new(),
            first_ts: None,
            window: Vec::new(),
            fin: Vec::new(),
            syn: Vec::new(),
            rst: Vec::new(),
            psh: Vec::new(),
            ack: Vec::new(),
            urg: Vec::new(),
            cwr: Vec::new(),
            ece: Vec::new(),
            ttl: Vec::new(),
            ip_df: Vec::new(),
            ip_mf: Vec::new(),
        }
    }

    fn vec_to_string<T: ToString>(v: &[T]) -> String {
        let inner = v.iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>()
            .join(",");
        format!("\"[{}]\"", inner)
    }
}

impl FlowFeature for PacketSequence {
    fn update(&mut self, packet: &PacketFeatures, fwd: bool, _last_ts: i64) {
        let ts = packet.timestamp_us;

        // Initialize the time of the first package
        let first = self.first_ts.get_or_insert(ts);

        self.dirs.push(if fwd { 1 } else { -1 });
        // Packet length
        self.lens.push(packet.length as i32);

        // Relative time
        self.timestamps.push(ts - *first);

        // ===== TCP window =====
        self.window.push(packet.window_size);

        // ===== TCP flags =====
        self.fin.push(packet.fin_flag);
        self.syn.push(packet.syn_flag);
        self.rst.push(packet.rst_flag);
        self.psh.push(packet.psh_flag);
        self.ack.push(packet.ack_flag);
        self.urg.push(packet.urg_flag);
        self.cwr.push(packet.cwr_flag);
        self.ece.push(packet.ece_flag);

        // ===== IP =====
        self.ttl.push(packet.ttl);
        self.ip_df.push(packet.ip_df);
        self.ip_mf.push(packet.ip_mf);
    }

    fn close(&mut self, _timestamp: i64, _cause: FlowExpireCause) {}

    fn dump(&self) -> String {
        format!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            Self::vec_to_string(&self.dirs),
            // Pure packet length sequence
            Self::vec_to_string(
                &self.lens.iter().map(|v| v.abs()).collect::<Vec<_>>()
            ),
            // Time series sequence
            Self::vec_to_string(&self.timestamps),

            Self::vec_to_string(&self.window),
            Self::vec_to_string(&self.fin),
            Self::vec_to_string(&self.syn),
            Self::vec_to_string(&self.rst),
            Self::vec_to_string(&self.psh),
            Self::vec_to_string(&self.ack),
            Self::vec_to_string(&self.urg),
            Self::vec_to_string(&self.cwr),
            Self::vec_to_string(&self.ece),

            Self::vec_to_string(&self.ttl),
            Self::vec_to_string(&self.ip_df),
            Self::vec_to_string(&self.ip_mf),
        )
    }

    fn headers() -> String
    where
        Self: Sized,
    {
        [
            "pkt_dir_seq",
            "pkt_len_seq",
            "pkt_usec_seq",

            "tcp_window_seq",
            "fin_seq","syn_seq","rst_seq","psh_seq",
            "ack_seq","urg_seq","cwr_seq","ece_seq",

            "ttl_seq","ip_df_seq","ip_mf_seq",
        ].join(",")
    }
}

/// Used by Lexnetflow
impl PacketSequence {
    pub fn dump_dir_len(&self) -> String {
        format!(
            "{},{}",
            Self::vec_to_string(&self.dirs),
            Self::vec_to_string(
                &self.lens.iter().map(|v| v.abs()).collect::<Vec<_>>()
            ),
        )
    }

    pub fn headers_dir_len() -> String {
        "pkt_dir_seq,pkt_len_seq".to_string()
    }
}
