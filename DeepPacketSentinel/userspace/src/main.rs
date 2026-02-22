use anyhow::{Context, Result};
use aya::{
    maps::{HashMap, RingBuf},
    programs::{Xdp, XdpFlags},
    Ebpf,
};
use aya_log::EbpfLogger;
use clap::Parser;
use common::{FlowMetadata, TokenBucket};
use log::{error, info, warn};
use std::sync::Arc;
use std::time::Duration;
use tokio::signal;
use tokio::sync::Mutex;

mod engine;
use engine::normalization::Normalizer;
use engine::policy::PolicyEngine;
use engine::protocol::{MockProtocolEngine, ProtocolEngine};
use engine::kronos_sender::{new_shared_sender, SharedKronosSender, DEFAULT_SOCKET_PATH};

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "lo")]
    iface: String,

    #[clap(long, default_value = "redis://127.0.0.1/")]
    redis: String,

    /// Unix socket path for Kronos IPC (set to empty string to disable).
    #[clap(long, default_value = DEFAULT_SOCKET_PATH)]
    kronos_socket: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let opt = Opt::parse();

    info!("Loading eBPF program...");
    let release_path = "target/bpfel-unknown-none/release/ebpf";
    let debug_path = "target/bpfel-unknown-none/debug/ebpf";

    let path = if std::path::Path::new(release_path).exists() {
        release_path
    } else {
        debug_path
    };

    let mut bpf = Ebpf::load_file(path).context(format!(
        "Failed to load eBPF file at '{}'. Did you run 'cargo build -p ebpf ...'?",
        path
    ))?;

    if let Err(e) = EbpfLogger::init(&mut bpf) {
        warn!("failed to initialize eBPF logger: {}", e);
    }

    // Attach XDP program
    let program: &mut Xdp = bpf
        .program_mut("xdp_firewall")
        .context("program 'xdp_firewall' not found")?
        .try_into()?;
    program.load()?;
    program
        .attach(&opt.iface, XdpFlags::SKB_MODE)
        .context("failed to attach the XDP program")?;

    info!("DeepPacketSentinel attached to interface: {}", opt.iface);

    // Initialize Maps
    let block_map = bpf.take_map("BLOCKLIST").context("BLOCKLIST map not found")?;
    let blocklist = Arc::new(Mutex::new(HashMap::try_from(block_map)?));

    let rate_map = bpf
        .take_map("RATE_LIMIT")
        .context("RATE_LIMIT map not found")?;
    let rate_limit = Arc::new(Mutex::new(HashMap::try_from(rate_map)?));

    let ring_map = bpf.take_map("TELEMETRY").context("TELEMETRY map not found")?;
    let mut ring_buf = RingBuf::try_from(ring_map)?;

    // Initialize Engines
    let policy_engine =
        Arc::new(PolicyEngine::new(&opt.redis).await.context("Failed to connect to Redis")?);
    let protocol_engine = Arc::new(MockProtocolEngine::new());

    info!("Engines initialized. Starting Control Loop...");

    // Kronos IPC sender — best-effort, non-blocking
    let kronos_sender = if !opt.kronos_socket.is_empty() {
        info!("Kronos IPC enabled → {}", opt.kronos_socket);
        Some(new_shared_sender(&opt.kronos_socket))
    } else {
        info!("Kronos IPC disabled (--kronos-socket not set)");
        None
    };

    // Control Loop
    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                info!("Exiting...");
                break;
            }
            _ = process_ring_buf(&mut ring_buf, &protocol_engine, &policy_engine, &blocklist, &rate_limit, kronos_sender.as_ref()) => {}
        }
    }

    Ok(())
}

async fn process_ring_buf(
    ring_buf: &mut RingBuf<aya::maps::MapData>,
    protocol_engine: &Arc<MockProtocolEngine>,
    policy_engine: &Arc<PolicyEngine>,
    blocklist: &Arc<Mutex<HashMap<aya::maps::MapData, u32, u32>>>,
    rate_limit: &Arc<Mutex<HashMap<aya::maps::MapData, u32, TokenBucket>>>,
    kronos_sender: Option<&SharedKronosSender>,
) {
    let mut processed = 0;
    // Drain the buffer as much as possible
    while let Some(item) = ring_buf.next() {
        processed += 1;
        // Parse metadata
        // Safety: We rely on eBPF sending correct struct
        if item.len() >= std::mem::size_of::<FlowMetadata>() {
            let flow: FlowMetadata =
                unsafe { std::ptr::read_unaligned(item.as_ptr() as *const FlowMetadata) };

            // 1. Identify App
            let app_id = protocol_engine.identify_app(&flow);

            // 2. Assess Risk
            let score = policy_engine.assess_risk(&flow, app_id);

            // 3. Enforce Policy
            {
                let mut bl = blocklist.lock().await;
                let mut rl = rate_limit.lock().await;
                if let Err(e) =
                    policy_engine.enforce_policy(&flow, app_id, score, &mut *bl, &mut *rl).await
                {
                    error!("Policy Enforcement Failed: {}", e);
                }
            }

            // 4. Forward to Kronos (best-effort — non-blocking)
            if let Some(sender) = kronos_sender {
                if let Ok(mut s) = sender.lock() {
                    s.send(&flow);
                }
            }
        }
    }

    if processed == 0 {
        // Sleep briefly to avoid 100% CPU if empty
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}
