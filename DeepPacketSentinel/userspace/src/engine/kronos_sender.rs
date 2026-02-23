//! Kronos IPC Sender — Forwards flow records to the Argus Kronos bridge.
//!
//! DeepPacketSentinel operates in kernel-space via eBPF/XDP and surfaces
//! `FlowMetadata` structs through a ring buffer to userspace.  This module
//! takes each flow record, serialises it as a newline-terminated JSON frame,
//! and sends it over a Unix domain socket to the Kronos Python process.
//!
//! # Socket protocol
//! One UTF-8 JSON object per line (`\n`-terminated).  Kronos's `IPCListener`
//! (Python) reads these frames and routes each flow through the meta-model.
//!
//! # Design choices
//! * **Non-blocking / best-effort**: if Kronos is not running or the write
//!   fails, DPS logs a warning and continues.  Kronos is an enhancement, not
//!   a hard dependency.
//! * **Lazy connect**: the sender reconnects automatically if the socket
//!   disappears (e.g. Kronos restart).
//! * **Payload encoding**: `payload` bytes are base64-encoded so they survive
//!   JSON transport cleanly.

use anyhow::Result;
use common::FlowMetadata;
use log::{debug, warn};
use serde::Serialize;
use std::os::unix::net::UnixStream;
use std::io::Write;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Default socket path — must match `IPCListener` in Kronos Python.
pub const DEFAULT_SOCKET_PATH: &str = "/var/run/argus_v/dps_kronos.sock";

/// MessagePack frame sent to Kronos for each flow.
#[derive(Serialize)]
struct FlowFrame<'a> {
    src_ip: String,
    dst_ip: String,
    src_port: u16,
    dst_port: u16,
    protocol: &'a str,
    bytes_in: u32,
    bytes_out: u32,
    duration: f32,
    /// Raw payload bytes
    #[serde(with = "serde_bytes")]
    payload: Option<&'a [u8]>,
}

/// Maps the raw `protocol` u32 from eBPF to a human-readable string.
fn proto_name(proto: u32) -> &'static str {
    match proto {
        6  => "TCP",
        17 => "UDP",
        1  => "ICMP",
        _  => "OTHER",
    }
}

/// Converts a big-endian u32 IP to dotted-decimal string.
fn ip_to_string(ip_be: u32) -> String {
    Ipv4Addr::from(ip_be.to_be_bytes()).to_string()
}

// ---------------------------------------------------------------------------
// KronosSender
// ---------------------------------------------------------------------------

/// Lazily-connected Unix socket sender.
///
/// Wrap in `Arc<Mutex<KronosSender>>` and share across async tasks.
pub struct KronosSender {
    socket_path: String,
    stream: Option<UnixStream>,
}

impl KronosSender {
    pub fn new(socket_path: &str) -> Self {
        Self {
            socket_path: socket_path.to_string(),
            stream: None,
        }
    }

    /// Send a `FlowMetadata` record to Kronos.
    ///
    /// Silently drops the frame if Kronos is unreachable — DPS keeps running.
    pub fn send(&mut self, flow: &FlowMetadata) {
        let payload_slice = if flow.payload_len > 0 {
            let len = (flow.payload_len as usize).min(flow.payload.len());
            Some(&flow.payload[..len])
        } else {
            None
        };

        let frame = FlowFrame {
            src_ip: ip_to_string(flow.src_ip),
            dst_ip: ip_to_string(flow.dst_ip),
            src_port: flow.src_port,
            dst_port: flow.dst_port,
            protocol: proto_name(flow.protocol),
            bytes_in: flow.payload_len,
            bytes_out: 0,  // DPS doesn't track egress bytes (yet)
            duration: 0.0, // DPS sees individual packets, not flows
            payload: payload_slice,
        };

        let mut buf = Vec::new();
        if let Err(e) = rmp_serde::encode::write_named(&mut buf, &frame) {
            warn!("[kronos] MessagePack serialise failed: {}", e);
            return;
        }

        if self.write_frame(&buf).is_err() {
            // Retry once after reconnect
            self.stream = None;
            if self.write_frame(&buf).is_err() {
                debug!("[kronos] Kronos not reachable — frame dropped");
            }
        }
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn write_frame(&mut self, data: &[u8]) -> Result<()> {
        let stream = self.get_or_connect()?;
        stream.write_all(data)?;
        Ok(())
    }

    fn get_or_connect(&mut self) -> Result<&mut UnixStream> {
        if self.stream.is_none() {
            let s = UnixStream::connect(&self.socket_path)?;
            s.set_write_timeout(Some(Duration::from_millis(50)))?;
            self.stream = Some(s);
            debug!("[kronos] Connected to Kronos at {}", self.socket_path);
        }
        Ok(self.stream.as_mut().unwrap())
    }
}

// ---------------------------------------------------------------------------
// Shared handle for use across async tasks
// ---------------------------------------------------------------------------

pub type SharedKronosSender = Arc<Mutex<KronosSender>>;

/// Construct a `SharedKronosSender` with the default socket path.
pub fn new_shared_sender(socket_path: &str) -> SharedKronosSender {
    Arc::new(Mutex::new(KronosSender::new(socket_path)))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use common::FlowMetadata;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct FlowFrameOwned {
        src_ip: String,
        dst_ip: String,
        src_port: u16,
        dst_port: u16,
        protocol: String,
        bytes_in: u32,
        bytes_out: u32,
        duration: f32,
        #[serde(with = "serde_bytes")]
        payload: Option<Vec<u8>>,
    }

    /// Build a synthetic flow and verify the MessagePack frame fields are correct.
    #[test]
    fn test_flow_frame_serialization() {
        // Build a flow: TCP, 1.2.3.4 -> 5.6.7.8, port 80
        let mut flow = FlowMetadata {
            src_ip: u32::from_be_bytes([1, 2, 3, 4]),
            dst_ip: u32::from_be_bytes([5, 6, 7, 8]),
            src_port: 54321,
            dst_port: 80,
            protocol: 6, // TCP
            payload_len: 3,
            payload: [0u8; 128],
        };
        flow.payload[0] = b'G';
        flow.payload[1] = b'E';
        flow.payload[2] = b'T';

        let len = (flow.payload_len as usize).min(flow.payload.len());
        let payload_slice = Some(&flow.payload[..len]);

        let frame = FlowFrame {
            src_ip: ip_to_string(flow.src_ip),
            dst_ip: ip_to_string(flow.dst_ip),
            src_port: flow.src_port,
            dst_port: flow.dst_port,
            protocol: proto_name(flow.protocol),
            bytes_in: flow.payload_len,
            bytes_out: 0,
            duration: 0.0,
            payload: payload_slice,
        };

        let mut buf = Vec::new();
        rmp_serde::encode::write_named(&mut buf, &frame).expect("serialization failed");

        // Deserialize and check
        let deser: FlowFrameOwned = rmp_serde::from_slice(&buf).expect("deserialization failed");

        assert_eq!(deser.src_ip, "1.2.3.4");
        assert_eq!(deser.dst_ip, "5.6.7.8");
        assert_eq!(deser.protocol, "TCP");
        assert_eq!(deser.dst_port, 80);
        assert_eq!(deser.payload, Some(vec![b'G', b'E', b'T']));
    }

    /// Verify that a zero-length payload produces correct output (null payload).
    #[test]
    fn test_flow_frame_empty_payload() {
        let flow = FlowMetadata {
            src_ip: 0,
            dst_ip: 0,
            src_port: 0,
            dst_port: 443,
            protocol: 6,
            payload_len: 0, // no payload
            payload: [0u8; 128],
        };

        let frame = FlowFrame {
            src_ip: ip_to_string(flow.src_ip),
            dst_ip: ip_to_string(flow.dst_ip),
            src_port: flow.src_port,
            dst_port: flow.dst_port,
            protocol: proto_name(flow.protocol),
            bytes_in: flow.payload_len,
            bytes_out: 0,
            duration: 0.0,
            payload: None, // empty payload → null
        };

        let mut buf = Vec::new();
        rmp_serde::encode::write_named(&mut buf, &frame).expect("serialization failed");

        let deser: FlowFrameOwned = rmp_serde::from_slice(&buf).expect("deserialization failed");
        assert_eq!(deser.payload, None);
    }

    /// End-to-end socket test (Linux only — requires Unix domain sockets).
    #[test]
    #[cfg(target_os = "linux")]
    fn test_send_over_unix_socket() {
        use std::io::{BufReader, Read};
        use std::os::unix::net::UnixListener;
        use std::sync::mpsc;

        let socket_path = "/tmp/dps_kronos_test.sock";

        // Clean up any leftover socket
        let _ = std::fs::remove_file(socket_path);

        let listener = UnixListener::bind(socket_path).expect("bind failed");

        let (tx, rx) = mpsc::channel::<Vec<u8>>();

        // Background thread: accept one connection, read everything
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept failed");
            // MessagePack is not newline-terminated, so we read available bytes or until EOF.
            // For this test, we expect one frame.
            let mut buf = vec![0u8; 1024];
            let n = stream.read(&mut buf).expect("read failed");
            tx.send(buf[..n].to_vec()).expect("send failed");
        });

        // Give the listener thread a moment
        std::thread::sleep(Duration::from_millis(50));

        // Send a flow frame
        let mut sender = KronosSender::new(socket_path);
        let flow = FlowMetadata {
            src_ip: u32::from_be_bytes([192, 168, 1, 1]),
            dst_ip: u32::from_be_bytes([10, 0, 0, 1]),
            src_port: 12345,
            dst_port: 22,
            protocol: 6,
            payload_len: 0,
            payload: [0u8; 128],
        };
        sender.send(&flow);

        // Receive what the listener captured
        let received = rx.recv_timeout(Duration::from_secs(2))
            .expect("timed out waiting for data");

        println!("[kronos test] Received bytes: {:?}", received);

        let deser: FlowFrameOwned = rmp_serde::from_slice(&received)
            .expect("received data is not valid MessagePack");

        assert_eq!(deser.src_ip, "192.168.1.1", "src_ip round-trip failed");
        assert_eq!(deser.dst_port, 22,           "dst_port round-trip failed");
        assert_eq!(deser.protocol, "TCP",         "protocol round-trip failed");
        assert_eq!(deser.payload, None, "empty payload should be null");

        // Cleanup
        let _ = std::fs::remove_file(socket_path);
    }
}
