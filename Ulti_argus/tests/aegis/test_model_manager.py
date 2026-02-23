"""Unit tests for Aegis shield runtime model manager.

This module provides comprehensive unit tests for the ModelManager class
in Ulti_argus/src/argus_v/aegis/model_manager.py.
"""

import sys
import os
import unittest
import tempfile
import shutil
import pickle
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch, ANY

# Mock firebase_admin modules BEFORE importing argus_v modules
sys.modules['firebase_admin'] = MagicMock()
sys.modules['firebase_admin.credentials'] = MagicMock()
sys.modules['firebase_admin.storage'] = MagicMock()
sys.modules['google.cloud'] = MagicMock()
sys.modules['google.cloud.storage'] = MagicMock()

# Import dependencies after mocking
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# Import the module under test
from argus_v.aegis.model_manager import (
    ModelManager,
    ModelLoadError,
    ModelValidationError,
    ScalerValidationError
)
from argus_v.aegis.config import ModelConfig

class TestModelManager(unittest.TestCase):
    """Unit tests for ModelManager class."""

    def setUp(self):
        """Set up test fixtures."""
        # Create a temporary directory
        self.test_dir = tempfile.mkdtemp()
        self.model_dir = os.path.join(self.test_dir, "models")
        self.scaler_dir = os.path.join(self.test_dir, "scalers")
        self.foundation_dir = os.path.join(self.test_dir, "foundation")

        # Create mock configuration
        self.config = MagicMock()
        self.config.model_local_path = self.model_dir
        self.config.scaler_local_path = self.scaler_dir
        self.config.foundation_model_path = os.path.join(self.foundation_dir, "foundation_model.pkl")
        self.config.foundation_scaler_path = os.path.join(self.foundation_dir, "foundation_scaler.pkl")
        self.config.min_model_age_hours = 0
        self.config.max_model_age_days = 30
        self.config.anomaly_threshold = 0.7
        self.config.high_risk_threshold = 0.9
        self.config.use_fallback_model = True

        # Create dummy foundation model and scaler
        os.makedirs(self.foundation_dir, exist_ok=True)

        self.feature_columns = [
            "bytes_in", "bytes_out", "packets_in", "packets_out",
            "duration", "src_port", "dst_port", "protocol"
        ]

        # Train a simple model
        X_train = np.random.rand(100, len(self.feature_columns))
        self.dummy_model = IsolationForest(random_state=42)
        self.dummy_model.fit(X_train)

        self.dummy_scaler = StandardScaler()
        self.dummy_scaler.fit(X_train)

        with open(self.config.foundation_model_path, 'wb') as f:
            pickle.dump(self.dummy_model, f)

        with open(self.config.foundation_scaler_path, 'wb') as f:
            pickle.dump(self.dummy_scaler, f)

        # Initialize ModelManager
        self.manager = ModelManager(self.config, feature_columns=self.feature_columns)

    def tearDown(self):
        """Tear down test fixtures."""
        shutil.rmtree(self.test_dir)

    def test_initialization(self):
        """Test ModelManager initialization and directory creation."""
        # Check if directories were created
        self.assertTrue(os.path.exists(self.model_dir))
        self.assertTrue(os.path.exists(self.scaler_dir))

        # Check attributes
        self.assertEqual(self.manager.feature_columns, self.feature_columns)
        self.assertEqual(self.manager.anomaly_threshold, 0.7)
        self.assertEqual(self.manager.high_risk_threshold, 0.9)
        self.assertIsNone(self.manager._model)
        self.assertIsNone(self.manager._scaler)

    @patch('argus_v.aegis.model_manager.FIREBASE_AVAILABLE', False)
    def test_list_remote_models_firebase_unavailable(self):
        """Test listing remote models when Firebase is unavailable."""
        models = self.manager._list_remote_models()
        self.assertEqual(models, [])

    def test_select_best_model(self):
        """Test selection of the best model based on age."""
        now = datetime.now()

        models = [
            {'name': 'old', 'timestamp': (now - timedelta(days=40)).strftime("%Y%m%d_%H%M%S")},
            {'name': 'new', 'timestamp': (now - timedelta(hours=1)).strftime("%Y%m%d_%H%M%S")},
            {'name': 'future', 'timestamp': (now + timedelta(days=1)).strftime("%Y%m%d_%H%M%S")}, # Should be ignored or handled?
            {'name': 'optimal', 'timestamp': (now - timedelta(days=2)).strftime("%Y%m%d_%H%M%S")},
        ]

        # Config: min 0 hours, max 30 days
        best = self.manager._select_best_model(models)
        self.assertEqual(best['name'], 'new') # Newest valid model

        # Test with min age constraint
        self.manager.config.min_model_age_hours = 24
        best = self.manager._select_best_model(models)
        self.assertEqual(best['name'], 'optimal') # 2 days old is > 24 hours

        # Test with no suitable models (all too old)
        self.manager.config.max_model_age_days = 1
        best = self.manager._select_best_model([models[0]]) # Only old model
        self.assertEqual(best['name'], 'old') # Should return newest anyway if no suitable found

    def test_download_model_artifacts_success(self):
        """Test successful model artifact download (simulated)."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        model_info = {'name': 'test_model', 'timestamp': timestamp}

        # The method creates mock files if they don't exist
        paths = self.manager._download_model_artifacts(model_info)

        self.assertIsNotNone(paths)
        self.assertTrue(os.path.exists(paths['model']))
        self.assertTrue(os.path.exists(paths['scaler']))
        self.assertIn(f"model_{timestamp}.pkl", paths['model'])

    def test_load_and_validate_model_success(self):
        """Test successful loading and validation of model/scaler."""
        paths = {
            'model': self.config.foundation_model_path,
            'scaler': self.config.foundation_scaler_path
        }

        result = self.manager._load_and_validate_model(paths)

        self.assertTrue(result)
        self.assertIsNotNone(self.manager._model)
        self.assertIsNotNone(self.manager._scaler)
        self.assertTrue(self.manager.is_model_available())

    def test_load_and_validate_model_invalid_file(self):
        """Test loading invalid model file."""
        # Create a corrupt file
        corrupt_path = os.path.join(self.test_dir, "corrupt.pkl")
        with open(corrupt_path, 'wb') as f:
            f.write(b"not a pickle")

        paths = {'model': corrupt_path, 'scaler': self.config.foundation_scaler_path}

        result = self.manager._load_and_validate_model(paths)
        self.assertFalse(result)
        self.assertIsNone(self.manager._model)

    def test_validate_model_checks(self):
        """Test model validation checks."""
        # Valid model
        self.manager._model = self.dummy_model
        self.assertTrue(self.manager._validate_model())

        # Invalid model: missing predict method
        class InvalidModel:
            pass
        self.manager._model = InvalidModel()
        self.assertFalse(self.manager._validate_model())

        # Invalid model: predicts wrong values
        class BadPredictModel:
            def predict(self, X):
                return np.zeros(len(X)) # Should be -1 or 1
            def decision_function(self, X):
                return np.zeros(len(X))
            def score_samples(self, X):
                return np.zeros(len(X))

        self.manager._model = BadPredictModel()
        # Mock scaler to avoid attribute error during validation
        self.manager._scaler = self.dummy_scaler
        self.assertFalse(self.manager._validate_model())

    def test_validate_scaler_checks(self):
        """Test scaler validation checks."""
        self.manager._scaler = self.dummy_scaler
        self.assertTrue(self.manager._validate_scaler())

        class InvalidScaler:
            pass
        self.manager._scaler = InvalidScaler()
        self.assertFalse(self.manager._validate_scaler())

        class BadShapeScaler:
            mean_ = [0] * len(self.feature_columns) # Needed to guess n_features
            def transform(self, X):
                return np.array([1]) # Wrong shape

        self.manager._scaler = BadShapeScaler()
        self.assertFalse(self.manager._validate_scaler())

    def test_load_latest_model_full_flow(self):
        """Test load_latest_model full flow with mocked remote listing."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        model_info = {'name': 'test_model', 'timestamp': timestamp}

        with patch.object(self.manager, '_list_remote_models', return_value=[model_info]), \
             patch.object(self.manager, '_download_model_artifacts') as mock_download:

            # Setup download to return valid paths (using our foundation files renamed)
            model_path = os.path.join(self.model_dir, f"model_{timestamp}.pkl")
            scaler_path = os.path.join(self.scaler_dir, f"scaler_{timestamp}.pkl")
            shutil.copy(self.config.foundation_model_path, model_path)
            shutil.copy(self.config.foundation_scaler_path, scaler_path)

            mock_download.return_value = {'model': model_path, 'scaler': scaler_path}

            self.assertTrue(self.manager.load_latest_model())
            self.assertTrue(self.manager.is_model_available())
            self.assertEqual(self.manager._model_metadata, model_info)

    def test_load_latest_model_fallback(self):
        """Test fallback to foundation model when remote load fails."""
        with patch.object(self.manager, '_list_remote_models', return_value=[]):
            # Should trigger fallback
            self.assertTrue(self.manager.load_latest_model())

            # Check if foundation model loaded
            self.assertTrue(self.manager.is_model_available())
            self.assertEqual(self.manager._model_metadata['type'], 'foundation')

    def test_load_latest_model_random_fallback(self):
        """Test fallback to random model when foundation model is missing."""
        # Remove foundation model
        os.remove(self.config.foundation_model_path)

        with patch.object(self.manager, '_list_remote_models', return_value=[]):
            self.assertTrue(self.manager.load_latest_model())

            # Should have generated a random fallback model
            self.assertTrue(self.manager.is_model_available())
            # Random fallback logic doesn't set metadata type to foundation
            # It sets failure count > 0
            self.assertGreater(self.manager._load_failures, 0)

    def test_hot_load_model(self):
        """Test hot loading a model."""
        # Create a new model file
        new_model_path = os.path.join(self.test_dir, "new_model.pkl")
        with open(new_model_path, 'wb') as f:
            pickle.dump(self.dummy_model, f)

        self.assertTrue(self.manager.hot_load_model(new_model_path, self.config.foundation_scaler_path))
        self.assertTrue(self.manager.is_model_available())
        self.assertEqual(self.manager._model_metadata['type'], 'hot_swap')

    def test_hot_load_model_failure(self):
        """Test hot load failure with invalid path."""
        self.assertFalse(self.manager.hot_load_model("nonexistent.pkl", "nonexistent.pkl"))

    def test_predict_flows(self):
        """Test making predictions on flows."""
        # Load model first
        self.manager._model = self.dummy_model
        self.manager._scaler = self.dummy_scaler

        # Create test dataframe
        df = pd.DataFrame(np.random.rand(10, len(self.feature_columns)), columns=self.feature_columns)
        # Add protocol as string to test mapping
        df['protocol'] = 'TCP'

        result = self.manager.predict_flows(df)

        self.assertIn('prediction', result.columns)
        self.assertIn('anomaly_score', result.columns)
        self.assertIn('risk_level', result.columns)

        # Check risk levels are valid strings
        valid_risks = ['low', 'medium', 'high', 'critical']
        self.assertTrue(all(r in valid_risks for r in result['risk_level']))

    def test_predict_flows_no_model(self):
        """Test predict flows raises error when no model loaded."""
        with self.assertRaises(ModelLoadError):
            self.manager.predict_flows(pd.DataFrame())

    def test_extract_features(self):
        """Test feature extraction."""
        df = pd.DataFrame({
            'bytes_in': [100],
            'bytes_out': [200],
            'packets_in': [10],
            'packets_out': [20],
            'duration': [1.0],
            'src_port': [80],
            'dst_port': [443],
            'protocol': ['TCP'],
            'extra_col': ['ignore']
        })

        features = self.manager._extract_features(df)

        self.assertEqual(list(features.columns), self.feature_columns)
        self.assertEqual(features.iloc[0]['protocol'], 1) # TCP -> 1

    def test_extract_features_missing_columns(self):
        """Test feature extraction with missing columns."""
        df = pd.DataFrame({'bytes_in': [100]})
        with self.assertRaises(ValueError):
            self.manager._extract_features(df)

    def test_explain_anomaly(self):
        """Test anomaly explanation logic."""
        self.manager._scaler = self.dummy_scaler

        # Create a flow series
        flow = pd.Series(np.random.rand(len(self.feature_columns)), index=self.feature_columns)

        explanation = self.manager.explain_anomaly(flow)
        self.assertIsInstance(explanation, list)
        self.assertTrue(len(explanation) > 0)
        self.assertIn("σ", explanation[0]) # Check for sigma symbol in explanation

    def test_get_model_info(self):
        """Test getting model info."""
        self.manager._model = self.dummy_model
        self.manager._scaler = self.dummy_scaler
        self.manager._last_load_time = datetime.now()

        info = self.manager.get_model_info()

        self.assertTrue(info['model_available'])
        self.assertEqual(info['model_type'], 'IsolationForest')
        self.assertEqual(info['scaler_type'], 'StandardScaler')
        self.assertIsNotNone(info['last_load_time'])

if __name__ == '__main__':
    unittest.main()
