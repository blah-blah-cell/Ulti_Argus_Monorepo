from unittest.mock import Mock

import pandas as pd

from argus_v.aegis.config import PollingConfig, PredictionConfig
from argus_v.aegis.prediction_engine import PredictionEngine


class TestTrustedIPSuppression:
    def setup_method(self):
        self.polling_config = PollingConfig()
        self.prediction_config = PredictionConfig()
        self.mock_model_manager = Mock()
        self.mock_blacklist_manager = Mock()
        self.mock_feedback_manager = Mock()

        self.prediction_engine = PredictionEngine(
            polling_config=self.polling_config,
            prediction_config=self.prediction_config,
            model_manager=self.mock_model_manager,
            blacklist_manager=self.mock_blacklist_manager,
            feedback_manager=self.mock_feedback_manager
        )

        # Configure mocks
        self.mock_blacklist_manager.is_blacklisted.return_value = False
        self.mock_blacklist_manager.add_to_blacklist.return_value = True

        # Mock explain_anomaly to return something
        self.mock_model_manager.explain_anomaly.return_value = ["test explanation"]

    def test_trusted_ip_suppression(self):
        """Test that trusted IPs do not generate anomalies."""
        # 1. Setup mock feedback manager logic
        # IP 1 is trusted, IP 2 is not
        self.mock_feedback_manager.is_trusted.side_effect = lambda ip: ip == '192.168.1.100'

        # 2. Create flow data with anomalies
        # Flow 1: Trusted IP (should be suppressed)
        # Flow 2: Untrusted IP (should be detected)
        flows_df = pd.DataFrame({
            'src_ip': ['192.168.1.100', '10.0.0.50'],
            'dst_ip': ['8.8.8.8', '1.1.1.1'],
            'src_port': [12345, 54321],
            'dst_port': [80, 443],
            'protocol': ['TCP', 'UDP'],
            'bytes_in': [1024, 2048],
            'bytes_out': [512, 1024],
            'packets_in': [10, 20],
            'packets_out': [5, 10],
            'duration': [30.5, 45.2],
            'prediction': [-1, -1],  # Both flagged by model
            'anomaly_score': [-0.9, -0.8],
            'risk_level': ['critical', 'high']
        })

        # 3. Process predictions directly
        self.prediction_engine._process_batch_predictions(flows_df)

        # 4. Verify results
        # Should only have 1 anomaly detected (the untrusted one)
        assert self.prediction_engine._stats['anomalies_detected'] == 1

        # Verify blacklist calls - only called for untrusted IP
        blacklist_calls = self.mock_blacklist_manager.add_to_blacklist.call_args_list

        # Verify untrusted IP was blacklisted
        untrusted_call = [c for c in blacklist_calls if c[1].get('ip_address') == '10.0.0.50']
        assert len(untrusted_call) == 1

        # Verify trusted IP was NOT blacklisted
        trusted_call = [c for c in blacklist_calls if c[1].get('ip_address') == '192.168.1.100']
        assert len(trusted_call) == 0
