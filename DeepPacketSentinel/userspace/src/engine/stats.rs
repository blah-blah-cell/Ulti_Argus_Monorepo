use anyhow::Result;
use aya::maps::PerCpuArray;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixListener;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct SentinelStats {
    pub passed_packets: u64,
    pub dropped_packets: u64,
    pub bytes_processed: u64,
}

pub trait StatsProvider: Send + Sync + 'static {
    fn collect_stats(&self) -> Result<SentinelStats>;
}

pub struct PerCpuStatsProvider {
    map: PerCpuArray<aya::maps::MapData, u64>,
}

impl PerCpuStatsProvider {
    pub fn new(map: PerCpuArray<aya::maps::MapData, u64>) -> Self {
        Self { map }
    }

    fn sum_per_cpu(map: &PerCpuArray<aya::maps::MapData, u64>, index: u32) -> Result<u64> {
        let values = map.get(&index, 0)?; // 0 flags
        Ok(values.iter().sum())
    }
}

impl StatsProvider for PerCpuStatsProvider {
    fn collect_stats(&self) -> Result<SentinelStats> {
        // Index 0: Passed, 1: Dropped, 2: Bytes
        let passed = Self::sum_per_cpu(&self.map, 0)?;
        let dropped = Self::sum_per_cpu(&self.map, 1)?;
        let bytes = Self::sum_per_cpu(&self.map, 2)?;

        Ok(SentinelStats {
            passed_packets: passed,
            dropped_packets: dropped,
            bytes_processed: bytes,
        })
    }
}

pub struct StatsExporter {
    provider: Arc<dyn StatsProvider>,
    socket_path: String,
}

impl StatsExporter {
    pub fn new(provider: impl StatsProvider, socket_path: &str) -> Self {
        Self {
            provider: Arc::new(provider),
            socket_path: socket_path.to_string(),
        }
    }

    pub async fn run(self) {
        let _ = std::fs::remove_file(&self.socket_path);
        let listener = match UnixListener::bind(&self.socket_path) {
            Ok(l) => l,
            Err(e) => {
                error!("Failed to bind stats socket at {}: {}", self.socket_path, e);
                return;
            }
        };

        info!("Stats Exporter running at {}", self.socket_path);

        let shared_stats = Arc::new(Mutex::new(SentinelStats::default()));

        // Spawn a task to update stats from provider
        let map_updater_stats = shared_stats.clone();
        let provider = self.provider.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            loop {
                interval.tick().await;
                match provider.collect_stats() {
                    Ok(stats) => {
                        let mut guard = map_updater_stats.lock().await;
                        *guard = stats;
                    }
                    Err(e) => error!("Failed to collect stats: {}", e),
                }
            }
        });

        // Handle connections
        loop {
            match listener.accept().await {
                Ok((mut socket, _)) => {
                    let current_stats = shared_stats.lock().await.clone();
                    if let Ok(json) = serde_json::to_string(&current_stats) {
                        let _ = socket.write_all(json.as_bytes()).await;
                    }
                }
                Err(e) => warn!("Stats connection failed: {}", e),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct MockStatsProvider {
        passed: AtomicU64,
    }

    impl StatsProvider for MockStatsProvider {
        fn collect_stats(&self) -> Result<SentinelStats> {
            Ok(SentinelStats {
                passed_packets: self.passed.load(Ordering::SeqCst),
                dropped_packets: 0,
                bytes_processed: 0,
            })
        }
    }

    #[tokio::test]
    #[cfg(target_os = "linux")]
    async fn test_stats_exporter() {
        let socket_path = "/tmp/dps_stats_test.sock";
        let provider = MockStatsProvider {
            passed: AtomicU64::new(42),
        };

        let exporter = StatsExporter::new(provider, socket_path);

        // Spawn exporter in background
        tokio::spawn(async move {
            exporter.run().await;
        });

        tokio::time::sleep(Duration::from_millis(1100)).await; // Wait for one tick (1s interval)

        // Connect and read
        let mut stream = tokio::net::UnixStream::connect(socket_path).await.expect("connect failed");
        let mut buf = String::new();
        stream.read_to_string(&mut buf).await.expect("read failed");

        let stats: SentinelStats = serde_json::from_str(&buf).expect("deserialize failed");
        assert_eq!(stats.passed_packets, 42);
    }
}
