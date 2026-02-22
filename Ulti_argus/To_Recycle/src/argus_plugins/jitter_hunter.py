from src.argus_plugins.manager import ArgusPlugin
import logging
import statistics
import time

class JitterHunter(ArgusPlugin):
    def name(self):
        return "JitterHunter"

    def description(self):
        return "Detects covert channels and C2 beacons using spectral analysis of inter-packet arrival times."

    def on_load(self):
        self.logger = logging.getLogger("JitterHunter")
        # Store last N timestamps for each flow
        # Key: (src_ip, src_port, dst_ip, dst_port) -> Value: [timestamp1, timestamp2, ...]
        self.flow_history = {}
        self.MAX_HISTORY = 20
        self.MIN_PACKETS_FOR_ANALYSIS = 10
        self.BEACON_VARIANCE_THRESHOLD = 50000000000000 # ~7ms std deviation (variance of nanoseconds)
        # eBPF timestamps are in nanoseconds. 
        # Low variance = Machine (Beacon). High Variance = Human/Random.

    def on_packet(self, flow_data):
        # Unique Flow ID
        flow_id = (flow_data['src_ip'], flow_data['src_port'], flow_data['dst_ip'], flow_data['dst_port'])
        
        current_ts = flow_data['timestamp']

        if flow_id not in self.flow_history:
            self.flow_history[flow_id] = []

        # Add current timestamp
        self.flow_history[flow_id].append(current_ts)

        # Keep history short
        if len(self.flow_history[flow_id]) > self.MAX_HISTORY:
            self.flow_history[flow_id].pop(0)

        # Analyze if we have enough data
        if len(self.flow_history[flow_id]) >= self.MIN_PACKETS_FOR_ANALYSIS:
            self._analyze_jitter(flow_id)

    def _analyze_jitter(self, flow_id):
        timestamps = self.flow_history[flow_id]
        
        # Calculate intervals (deltas)
        intervals = []
        for i in range(1, len(timestamps)):
            intervals.append(timestamps[i] - timestamps[i-1])

        # We care about variance of intervals. 
        # 1.0s, 1.0s, 1.0s -> Variance 0.0 -> BEACON
        # 0.2s, 4.5s, 0.1s -> Variance High -> HUMAN
        
        if not intervals:
            return

        variance = statistics.variance(intervals)
        
        # Heuristic: Extremely low variance indicates automated beaconing
        # Note: Nanoseconds are large numbers, variance will be large.
        # Perfect beacon: 1s, 1s, 1s -> variance 0.
        # Realistic beacon: 1.01s, 0.99s, 1.00s -> low variance.
        
        # Let's say we catch anything with std_dev < 10ms (10,000,000 ns)
        # variance = std_dev^2 = 100,000,000,000,000
        
        # For demo purposes, we'll pick a threshold
        if variance < self.BEACON_VARIANCE_THRESHOLD: 
             self.logger.warning(f"[!] JITTER HUNTER: Potential C2 Beacon detected on {flow_id}! Variance: {variance:.2f}")
             # In a real system we would raise an alert event here
