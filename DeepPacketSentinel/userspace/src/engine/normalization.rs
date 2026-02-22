use common::FlowMetadata;

pub struct Normalizer;

impl Normalizer {
    pub fn new() -> Self {
        Self
    }

    /// Normalizes the payload into a float vector [0.0, 1.0] of fixed size 128.
    /// Bytes are scaled by 255.0.
    pub fn normalize(&self, flow: &FlowMetadata) -> Vec<f32> {
        flow.payload.iter().map(|&b| b as f32 / 255.0).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::FlowMetadata;

    #[test]
    fn test_normalize_basic() {
        let normalizer = Normalizer::new();
        let mut flow = FlowMetadata {
            src_ip: 0,
            dst_ip: 0,
            src_port: 0,
            dst_port: 0,
            protocol: 0,
            payload_len: 4,
            payload: [0; 128],
        };
        // Mock payload
        flow.payload[0] = 0; // 0.0
        flow.payload[1] = 255; // 1.0
        flow.payload[2] = 127; // ~0.498
        flow.payload[3] = 51; // 0.2

        let vec = normalizer.normalize(&flow);
        assert_eq!(vec.len(), 128);
        assert_eq!(vec[0], 0.0);
        assert_eq!(vec[1], 1.0);
        assert!((vec[2] - 127.0 / 255.0).abs() < 0.0001);
        assert!((vec[3] - 0.2).abs() < 0.0001);
    }
}
