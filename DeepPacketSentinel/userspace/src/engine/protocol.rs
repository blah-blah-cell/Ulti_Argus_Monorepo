use common::FlowMetadata;
use serde::Serialize;

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub enum AppId {
    Unknown,
    SSH,
    TLS,
    BitTorrent,
    HTTP,
}

pub trait ProtocolEngine {
    fn identify_app(&self, flow: &FlowMetadata) -> AppId;
}

pub struct MockProtocolEngine;

impl MockProtocolEngine {
    pub fn new() -> Self {
        Self
    }
}

impl ProtocolEngine for MockProtocolEngine {
    fn identify_app(&self, flow: &FlowMetadata) -> AppId {
        // Mock logic: use ports or payload patterns
        match (flow.src_port, flow.dst_port) {
            (22, _) | (_, 22) => AppId::SSH,
            (443, _) | (_, 443) => AppId::TLS,
            (80, _) | (_, 80) => AppId::HTTP,
            (6881..=6889, _) | (_, 6881..=6889) => AppId::BitTorrent,
            _ => {
                // Peek at payload for magic bytes (very simple mock)
                if flow.payload_len >= 3 {
                    let p = &flow.payload;
                    if p[0] == 0x16 && p[1] == 0x03 {
                        // TLS Handshake
                        return AppId::TLS;
                    }
                    if p[0] == b'G' && p[1] == b'E' && p[2] == b'T' {
                        return AppId::HTTP;
                    }
                }
                AppId::Unknown
            }
        }
    }
}
