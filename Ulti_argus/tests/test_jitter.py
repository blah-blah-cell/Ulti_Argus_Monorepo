import os
import sys

# Ensure src is in path so we can import modules when running directly
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../")))

import unittest
import unittest.mock

from argus_v.plugins.jitter_hunter import JitterHunter


class TestJitterHunter(unittest.TestCase):
    def setUp(self):
        self.plugin = JitterHunter()
        self.plugin.on_load()
        # Mock logger
        self.plugin.logger = unittest.mock.MagicMock()

    def test_beacon_detection(self):
        # Simulate perfect beacon (1.0s interval)
        # Nanoseconds: 1s = 1,000,000,000 ns
        start_time = 1000000000
        flow_data = {
            "src_ip": "192.168.1.100", "src_port": 12345,
            "dst_ip": "10.0.0.1", "dst_port": 80,
            "len": 64
        }

        # Send 15 packets with exact 1s interval
        for i in range(15):
             flow_data["timestamp"] = start_time + (i * 1000000000)
             self.plugin.on_packet(flow_data)

        # Should have triggered alert
        self.plugin.logger.warning.assert_called()
        args, _ = self.plugin.logger.warning.call_args
        self.assertIn("Potential C2 Beacon", args[0])

    def test_human_traffic(self):
        # Simulate bursty traffic
        start_time = 1000000000
        intervals = [0.1, 2.5, 0.3, 0.1, 5.0, 0.2, 0.5, 0.1, 0.1, 3.0]
        
        flow_data = {
            "src_ip": "192.168.1.101", "src_port": 54321,
            "dst_ip": "10.0.0.1", "dst_port": 443,
            "len": 500
        }
        
        current = start_time
        for interval in intervals:
            current += int(interval * 1000000000)
            flow_data["timestamp"] = current
            self.plugin.on_packet(flow_data)

        # Should NOT trigger alert
        self.plugin.logger.warning.assert_not_called()

if __name__ == '__main__':
    unittest.main()
