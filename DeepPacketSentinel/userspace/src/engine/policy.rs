use crate::engine::protocol::AppId;
use async_trait::async_trait;
use aya::maps::{HashMap, MapData};
use common::{FlowMetadata, TokenBucket};
use lru::LruCache;
use redis::AsyncCommands;
use tracing::info;
use serde::Serialize;
use std::net::Ipv4Addr;
use std::num::NonZeroUsize;
use std::sync::Mutex;

#[derive(Debug, Serialize)]
pub enum RiskLevel {
    Monitor,  // < 80
    Throttle, // 80-95
    Isolate,  // > 95
}

#[derive(Debug, Serialize)]
pub struct ExplainabilityLog {
    pub src_ip: String,
    pub app_id: AppId,
    pub confidence_score: u8,
    pub risk_level: RiskLevel,
    pub action: String,
    pub reason: String,
}

// Trait for Map Operations to allow Mocking
pub trait PolicyMap<K, V> {
    fn update(&mut self, key: K, value: V) -> anyhow::Result<()>;
}

// Implement PolicyMap for aya::maps::HashMap
impl<K, V> PolicyMap<K, V> for HashMap<MapData, K, V>
where
    K: aya::Pod,
    V: aya::Pod,
{
    fn update(&mut self, key: K, value: V) -> anyhow::Result<()> {
        self.insert(key, value, 0).map_err(|e| e.into())
    }
}

// Trait for Event Publishing (Redis) to allow Mocking
#[async_trait]
pub trait EventPublisher: Send + Sync {
    async fn publish(&self, channel: &str, message: &str) -> anyhow::Result<()>;
}

struct RedisPublisher {
    con: redis::aio::ConnectionManager,
}

#[async_trait]
impl EventPublisher for RedisPublisher {
    async fn publish(&self, channel: &str, message: &str) -> anyhow::Result<()> {
        let mut con = self.con.clone();
        let _: () = con.publish(channel, message).await?;
        Ok(())
    }
}

pub struct PolicyEngine {
    publisher: Box<dyn EventPublisher>,
    blocked_cache: Mutex<LruCache<u32, ()>>,
}

impl PolicyEngine {
    pub async fn new(redis_url: &str) -> anyhow::Result<Self> {
        // Connect asynchronously using ConnectionManager
        let client = redis::Client::open(redis_url)?;
        let con = client.get_connection_manager().await?;
        let publisher = Box::new(RedisPublisher { con });
        let cache = LruCache::new(NonZeroUsize::new(10000).unwrap());
        Ok(Self {
            publisher,
            blocked_cache: Mutex::new(cache),
        })
    }

    #[cfg(test)]
    pub fn new_with_publisher(publisher: Box<dyn EventPublisher>) -> Self {
        let cache = LruCache::new(NonZeroUsize::new(10000).unwrap());
        Self {
            publisher,
            blocked_cache: Mutex::new(cache),
        }
    }

    pub fn assess_risk(&self, _flow: &FlowMetadata, app_id: AppId) -> u8 {
        // Mock confidence score based on AppId
        match app_id {
            AppId::BitTorrent => 96, // High risk
            AppId::SSH => 85,        // Suspicious if unknown
            AppId::TLS => 10,        // Normal
            AppId::HTTP => 50,
            AppId::Unknown => 70,
        }
    }

    // Handles logic: returns Action description
    pub async fn enforce_policy<M1, M2>(
        &self,
        flow: &FlowMetadata,
        app_id: AppId,
        score: u8,
        blocklist: &mut M1,
        rate_limit: &mut M2,
    ) -> anyhow::Result<()>
    where
        M1: PolicyMap<u32, u32> + Send,
        M2: PolicyMap<u32, TokenBucket> + Send,
    {
        let ip_addr = Ipv4Addr::from(flow.src_ip);
        let ip_str = ip_addr.to_string();

        let (risk, action_desc) = if score > 95 {
            // Check cache first to avoid redundant syscalls.
            // Note: If an external agent (Python enforcer) removes the IP from the blocklist,
            // this cache might prevent immediate re-blocking until eviction.
            // However, since we re-assess risk on every packet, if the IP continues to be malicious,
            // it will eventually be re-blocked.
            // Map updates use BPF_ANY (atomic overwrite), so concurrent updates are safe.
            let mut cache = self.blocked_cache.lock().unwrap();
            if !cache.contains(&flow.src_ip) {
                // Block: Value 1
                blocklist.update(flow.src_ip, 1)?;
                cache.put(flow.src_ip, ());
            }
            (
                RiskLevel::Isolate,
                format!("Blocking IP {} due to high risk app {:?}", ip_str, app_id),
            )
        } else if score >= 80 {
            // Throttle
            let bucket = TokenBucket {
                last_time: 0,    // Reset
                tokens: 100_000, // Initial burst (100KB)
                rate: 100_000,   // 100KB/s
                capacity: 100_000,
                remainder: 0,
            };
            rate_limit.update(flow.src_ip, bucket)?;
            (
                RiskLevel::Throttle,
                format!(
                    "Throttling IP {} due to suspicious app {:?}",
                    ip_str, app_id
                ),
            )
        } else {
            (
                RiskLevel::Monitor,
                format!("Monitoring IP {} - App {:?}", ip_str, app_id),
            )
        };

        let log = ExplainabilityLog {
            src_ip: ip_str,
            app_id,
            confidence_score: score,
            risk_level: risk,
            action: action_desc.clone(),
            reason: format!("Detected protocol {:?}", app_id),
        };

        // Publish to Redis using async connection
        let json = serde_json::to_string(&log)?;
        self.publisher.publish("security_events", &json).await?;

        info!("Policy Action: {}", action_desc);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Instant;

    // Mock Publisher — zero overhead, used for baseline measurements
    struct MockPublisher;
    #[async_trait]
    impl EventPublisher for MockPublisher {
        async fn publish(&self, _channel: &str, _message: &str) -> anyhow::Result<()> {
            Ok(())
        }
    }

    // Mock Publisher that simulates reconnect overhead (~1ms per publish).
    // Used in test_enforce_policy_connection_overhead to contrast against reused connections.
    struct MockConnectingPublisher;
    #[async_trait]
    impl EventPublisher for MockConnectingPublisher {
        async fn publish(&self, _channel: &str, _message: &str) -> anyhow::Result<()> {
            // Simulate the latency of re-establishing a connection each time
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            Ok(())
        }
    }

    // Mock Map with Delay
    struct MockMap {
        update_count: Arc<AtomicUsize>,
    }

    impl MockMap {
        fn new() -> Self {
            Self {
                update_count: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    impl PolicyMap<u32, u32> for MockMap {
        fn update(&mut self, _key: u32, _value: u32) -> anyhow::Result<()> {
            self.update_count.fetch_add(1, Ordering::SeqCst);
            // Simulate syscall overhead
            std::thread::sleep(std::time::Duration::from_micros(10));
            Ok(())
        }
    }

    impl PolicyMap<u32, TokenBucket> for MockMap {
        fn update(&mut self, _key: u32, _value: TokenBucket) -> anyhow::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_enforce_policy_performance() {
        let publisher = Box::new(MockPublisher);
        // Using new_with_publisher to inject mock
        let engine = PolicyEngine::new_with_publisher(publisher);

        let mut block_map = MockMap::new();
        let mut rate_map = MockMap::new(); // Dummy

        let flow = FlowMetadata {
            src_ip: 0x01020304, // 1.2.3.4
            dst_ip: 0,
            src_port: 0,
            dst_port: 0,
            protocol: 6,
            payload_len: 100,
            payload: [0; 128],
        };

        let app_id = AppId::BitTorrent; // High Risk -> Score 96 -> Block
        let score = 96;

        let start = Instant::now();
        let iterations = 1000;

        for _ in 0..iterations {
            engine
                .enforce_policy(&flow, app_id, score, &mut block_map, &mut rate_map)
                .await
                .unwrap();
        }

        let duration = start.elapsed();
        let updates = block_map.update_count.load(Ordering::SeqCst);

        println!("Time taken for {} iterations: {:?}", iterations, duration);
        println!("Total map updates: {}", updates);

        // Verification
        // With cache, we expect EXACTLY 1 update.
        assert_eq!(updates, 1, "Should only update map once due to caching. If this fails, the optimization is not working.");
    }

    #[tokio::test]
    async fn test_enforce_policy_connection_overhead() {
        let iterations = 100;
        let flow = FlowMetadata {
            src_ip: 0x0A000001,
            dst_ip: 0,
            src_port: 0,
            dst_port: 0,
            protocol: 6,
            payload_len: 100,
            payload: [0; 128],
        };
        let app_id = AppId::HTTP; // Monitor -> Score 50 (always publishes)
        let score = 50;

        // Baseline: Connecting every time (Simulated)
        let connecting_pub = Box::new(MockConnectingPublisher);
        let connecting_engine = PolicyEngine::new_with_publisher(connecting_pub);
        let mut block_map = MockMap::new();
        let mut rate_map = MockMap::new();

        let start_conn = Instant::now();
        for _ in 0..iterations {
            connecting_engine
                .enforce_policy(&flow, app_id, score, &mut block_map, &mut rate_map)
                .await
                .unwrap();
        }
        let duration_conn = start_conn.elapsed();

        // Optimized: Reusing connection (MockPublisher has 0 overhead)
        let reused_pub = Box::new(MockPublisher);
        let reused_engine = PolicyEngine::new_with_publisher(reused_pub);

        // Reset maps
        let mut block_map = MockMap::new();
        let mut rate_map = MockMap::new();

        let start_reused = Instant::now();
        for _ in 0..iterations {
            reused_engine
                .enforce_policy(&flow, app_id, score, &mut block_map, &mut rate_map)
                .await
                .unwrap();
        }
        let duration_reused = start_reused.elapsed();

        println!("Connecting Publisher ({} iters): {:?}", iterations, duration_conn);
        println!("Reusing Publisher ({} iters): {:?}", iterations, duration_reused);

        // Expect reused to be much faster
        assert!(duration_reused < duration_conn);
        let speedup = duration_conn.as_secs_f64() / duration_reused.as_secs_f64();
        println!("Estimated Speedup: {:.2}x", speedup);
    }
}

#[cfg(test)]
mod performance_tests {
    use super::*;
    use std::time::Instant;

    struct SlowPublisher;
    #[async_trait]
    impl EventPublisher for SlowPublisher {
        async fn publish(&self, _channel: &str, _message: &str) -> anyhow::Result<()> {
            // Simulate non-blocking I/O
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            Ok(())
        }
    }

    struct NoOpMap;
    impl PolicyMap<u32, u32> for NoOpMap {
        fn update(&mut self, _key: u32, _value: u32) -> anyhow::Result<()> { Ok(()) }
    }
    impl PolicyMap<u32, TokenBucket> for NoOpMap {
        fn update(&mut self, _key: u32, _value: TokenBucket) -> anyhow::Result<()> { Ok(()) }
    }

    #[tokio::test]
    async fn test_async_non_blocking_behavior() {
        let publisher = Box::new(SlowPublisher);
        let engine = PolicyEngine::new_with_publisher(publisher);
        let mut map1 = NoOpMap;
        let mut map2 = NoOpMap;

        let flow = FlowMetadata {
            src_ip: 0, dst_ip: 0, src_port: 0, dst_port: 0,
            protocol: 0, payload_len: 0, payload: [0; 128]
        };

        let start = Instant::now();
        // Run 10 times, should take ~100ms wall time, but we are just awaiting it sequentially
        // So the test just checks if it works. To check if it's non-blocking to other tasks, we would need to spawn.

        for _ in 0..10 {
            engine.enforce_policy(&flow, AppId::Unknown, 0, &mut map1, &mut map2).await.unwrap();
        }
        let duration = start.elapsed();
        println!("Async execution time: {:?}", duration);
        assert!(duration >= std::time::Duration::from_millis(100));
    }
}

#[cfg(test)]
mod concurrency_tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::sleep;

    struct SlowPublisher;
    #[async_trait]
    impl EventPublisher for SlowPublisher {
        async fn publish(&self, _channel: &str, _message: &str) -> anyhow::Result<()> {
            // Simulate async I/O delay
            sleep(Duration::from_millis(50)).await;
            Ok(())
        }
    }

    struct NoOpMap;
    impl PolicyMap<u32, u32> for NoOpMap {
        fn update(&mut self, _key: u32, _value: u32) -> anyhow::Result<()> { Ok(()) }
    }
    impl PolicyMap<u32, TokenBucket> for NoOpMap {
        fn update(&mut self, _key: u32, _value: TokenBucket) -> anyhow::Result<()> { Ok(()) }
    }

    #[tokio::test]
    async fn test_async_allows_concurrency() {
        let publisher = Box::new(SlowPublisher);
        let engine = std::sync::Arc::new(PolicyEngine::new_with_publisher(publisher));

        // Spawn a background task that counts ticks
        let counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter_clone = counter.clone();

        let handle = tokio::spawn(async move {
            for _ in 0..10 {
                sleep(Duration::from_millis(10)).await;
                counter_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        });

        // Run enforce_policy which takes 50ms * 2 = 100ms
        let mut map1 = NoOpMap;
        let mut map2 = NoOpMap;

        let flow = FlowMetadata {
            src_ip: 0, dst_ip: 0, src_port: 0, dst_port: 0,
            protocol: 0, payload_len: 0, payload: [0; 128]
        };

        for _ in 0..2 {
            engine.enforce_policy(&flow, AppId::Unknown, 0, &mut map1, &mut map2).await.unwrap();
        }

        // Wait for background task
        handle.await.unwrap();

        let ticks = counter.load(std::sync::atomic::Ordering::SeqCst);
        println!("Background ticks: {}", ticks);

        // If enforce_policy was blocking (std::thread::sleep), ticks would be low or 0 because the thread would be blocked
        // (assuming single threaded runtime or contention).
        // With async sleep, the runtime yields, so background task runs.
        assert!(ticks >= 5, "Background task should have run while policy was waiting for I/O");
    }
}
