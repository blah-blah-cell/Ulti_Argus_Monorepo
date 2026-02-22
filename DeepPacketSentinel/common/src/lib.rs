#![no_std]

// Common types shared between eBPF kernel space and Userspace

pub type IPAddress = u32;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PacketLog {
    pub ipv4_address: u32,
    pub action: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FlowMetadata {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u32,
    pub payload_len: u32,
    pub payload: [u8; 128],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TokenBucket {
    pub last_time: u64, // Nanoseconds since boot
    pub tokens: u64,
    pub rate: u64,      // Tokens per second
    pub capacity: u64,
    pub remainder: u64, // Fractional tokens (scaled by 1_000_000_000)
}

impl TokenBucket {
    /// Updates the token bucket based on the time elapsed since the last update.
    /// Returns nothing, modifies `self` in place.
    #[inline(always)]
    pub fn refill(&mut self, now: u64) {
        let delta = now.wrapping_sub(self.last_time);

        // If delta is huge (> 1s), just fill up.
        // This avoids potential overflow in multiplication for large deltas
        // and handles long idle periods efficiently.
        if delta >= 1_000_000_000 {
            self.tokens = self.capacity;
            self.remainder = 0;
        } else {
             // Calculate produced tokens: (delta * rate + remainder) / 1_000_000_000
             // We use u64 which is safe for rates up to ~147 Gbps with delta < 1s.
             // (10^9 ns * 18.4*10^9 tokens/s = 1.84*10^19 < u64::MAX)
             let production = delta * self.rate + self.remainder;

             let tokens_added = production / 1_000_000_000;
             self.remainder = production % 1_000_000_000;

             self.tokens = self.tokens.saturating_add(tokens_added);
             if self.tokens > self.capacity {
                 self.tokens = self.capacity;
                 self.remainder = 0; // Clear remainder if bucket is full
             }
        }
        self.last_time = now;
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketLog {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FlowMetadata {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for TokenBucket {}
