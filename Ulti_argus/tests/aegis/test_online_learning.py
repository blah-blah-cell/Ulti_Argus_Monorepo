import sys
from unittest.mock import MagicMock

# Mock dependencies before importing the modules under test
sys.modules["numpy"] = MagicMock()
sys.modules["pandas"] = MagicMock()
sys.modules["sklearn"] = MagicMock()
sys.modules["sklearn.ensemble"] = MagicMock()
sys.modules["firebase_admin"] = MagicMock()
sys.modules["google.cloud"] = MagicMock()
sys.modules["yaml"] = MagicMock()
sys.modules["scapy.all"] = MagicMock() # Often used in network stuff

import json
import sqlite3
import threading
import time
import unittest
from pathlib import Path
from queue import Queue
from unittest.mock import patch

# Adjust path to import argus_v
sys.path.append("Ulti_argus/src")

# Now import the modules under test
from argus_v.aegis.daemon import OnlineLearningThread
from argus_v.aegis.prediction_engine import PredictionEngine
from argus_v.aegis.model_manager import ModelManager

class TestOnlineLearning(unittest.TestCase):
    def setUp(self):
        self.mock_model_manager = MagicMock(spec=ModelManager)
        self.mock_model_manager.feature_columns = ['f1', 'f2']
        self.mock_model_manager._model = MagicMock()

        self.mock_prediction_engine = MagicMock(spec=PredictionEngine)
        self.mock_prediction_engine.model_manager = self.mock_model_manager
        self.mock_prediction_engine.borderline_events_queue = Queue()
        self.mock_prediction_engine._model_lock = threading.Lock()

        self.db_path = Path("test_online_learning.db")
        if self.db_path.exists():
            self.db_path.unlink()

    def tearDown(self):
        if self.db_path.exists():
            self.db_path.unlink()

    def test_online_learning_buffering(self):
        # Create thread
        thread = OnlineLearningThread(self.mock_prediction_engine, self.db_path)

        # Add event to queue
        event = {
            'features': {'f1': 0.5, 'f2': 0.6},
            'score': 0.5,
            'timestamp': '2023-01-01T00:00:00'
        }
        self.mock_prediction_engine.borderline_events_queue.put(event)

        # Run processing manually
        thread._process_buffer()

        # Check DB
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT features, score FROM learning_buffer")
        row = cursor.fetchone()
        conn.close()

        self.assertIsNotNone(row)
        self.assertEqual(json.loads(row[0]), event['features'])
        self.assertEqual(row[1], event['score'])

    def test_trigger_partial_fit(self):
        # Setup model with partial_fit
        self.mock_model_manager._model.partial_fit = MagicMock()
        del self.mock_model_manager._model.warm_start # ensure it uses partial_fit path

        thread = OnlineLearningThread(self.mock_prediction_engine, self.db_path)
        thread.batch_size_trigger = 5  # Lower trigger for testing

        # Fill queue
        for i in range(5):
            event = {
                'features': {'f1': float(i), 'f2': float(i)},
                'score': 0.5,
                'timestamp': '2023-01-01T00:00:00'
            }
            self.mock_prediction_engine.borderline_events_queue.put(event)

        # Process
        thread._process_buffer()

        # Verify partial_fit called
        self.mock_model_manager._model.partial_fit.assert_called_once()
        args, _ = self.mock_model_manager._model.partial_fit.call_args
        # args[0] is the numpy array mock. Since numpy is mocked, we can't easily check values unless we check calls to np.array
        # But we can check that partial_fit was called with SOMETHING.
        self.assertTrue(len(args) > 0)

        # Verify buffer cleared
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM learning_buffer")
        count = cursor.fetchone()[0]
        conn.close()
        self.assertEqual(count, 0)

    def test_trigger_warm_start(self):
         # Setup model with warm_start
        del self.mock_model_manager._model.partial_fit # ensure it uses warm_start path
        self.mock_model_manager._model.warm_start = True
        self.mock_model_manager._model.fit = MagicMock()

        thread = OnlineLearningThread(self.mock_prediction_engine, self.db_path)
        thread.batch_size_trigger = 5

         # Fill queue
        for i in range(5):
            event = {
                'features': {'f1': float(i), 'f2': float(i)},
                'score': 0.5,
                'timestamp': '2023-01-01T00:00:00'
            }
            self.mock_prediction_engine.borderline_events_queue.put(event)

        thread._process_buffer()

        self.mock_model_manager._model.fit.assert_called_once()
        args, _ = self.mock_model_manager._model.fit.call_args
        self.assertTrue(len(args) > 0)

    def test_hot_swap_locking(self):
        # We need to test PredictionEngine.hot_swap_model
        # But PredictionEngine relies on imports we mocked.
        # We can instantiate it safely because dependencies are mocked.

        # However, PredictionEngine.__init__ validates arguments.
        # We can bypass __init__ or provide mocks.

        # We'll use a subclass or patch PredictionEngine to test just the method
        # Actually, we can just instantiate it with mocks.

        mock_polling_config = MagicMock()
        mock_prediction_config = MagicMock()
        mock_blacklist_manager = MagicMock()

        pe = PredictionEngine(
            polling_config=mock_polling_config,
            prediction_config=mock_prediction_config,
            model_manager=self.mock_model_manager,
            blacklist_manager=mock_blacklist_manager
        )

        # Mock hot_load_model
        pe.model_manager.hot_load_model.return_value = True

        # Spy on the lock
        pe._model_lock = MagicMock()
        pe._model_lock.__enter__ = MagicMock()
        pe._model_lock.__exit__ = MagicMock()

        pe.hot_swap_model("new_model.pkl")

        pe._model_lock.__enter__.assert_called_once()
        pe.model_manager.hot_load_model.assert_called_with("new_model.pkl", "new_scaler.pkl")
