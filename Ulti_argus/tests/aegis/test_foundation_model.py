import pickle
from unittest.mock import patch

import numpy as np
import pytest
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from argus_v.aegis.config import ModelConfig
from argus_v.aegis.model_manager import ModelManager


class TestFoundationModel:

    @pytest.fixture
    def foundation_artifacts(self, tmp_path):
        """Create dummy foundation model artifacts."""
        model_path = tmp_path / "foundation_model.pkl"
        scaler_path = tmp_path / "foundation_scaler.pkl"

        model = IsolationForest(n_estimators=10, random_state=42)
        model.fit(np.random.randn(100, 8))

        scaler = StandardScaler()
        scaler.fit(np.random.randn(100, 8))

        with open(model_path, 'wb') as f:
            pickle.dump(model, f)

        with open(scaler_path, 'wb') as f:
            pickle.dump(scaler, f)

        return str(model_path), str(scaler_path)

    def test_load_foundation_model_success(self, foundation_artifacts, tmp_path):
        """Test that foundation model is loaded when main model is missing."""
        model_path, scaler_path = foundation_artifacts

        # Use a temp dir that exists but is empty
        empty_models_dir = tmp_path / "models"
        empty_scalers_dir = tmp_path / "scalers"

        config = ModelConfig(
            model_local_path=str(empty_models_dir),
            scaler_local_path=str(empty_scalers_dir),
            foundation_model_path=model_path,
            foundation_scaler_path=scaler_path,
            use_fallback_model=True
        )

        manager = ModelManager(config)

        # Patch _list_remote_models to return empty list
        with patch.object(manager, '_list_remote_models', return_value=[]):
             success = manager.load_latest_model()

        assert success
        assert manager.is_model_available()

        info = manager.get_model_info()
        assert info['model_available'] is True

        # Check metadata to confirm it's the foundation model
        assert 'model_metadata' in info
        assert info['model_metadata']['type'] == 'foundation'
        assert info['model_metadata']['name'] == 'Foundation Model'

    def test_fallback_to_random_if_foundation_missing(self, tmp_path):
        """Test fallback to random noise if foundation model is also missing."""

        empty_models_dir = tmp_path / "models"
        empty_scalers_dir = tmp_path / "scalers"

        config = ModelConfig(
            model_local_path=str(empty_models_dir),
            scaler_local_path=str(empty_scalers_dir),
            foundation_model_path="/non/existent/foundation.pkl",
            foundation_scaler_path="/non/existent/foundation_scaler.pkl",
            use_fallback_model=True
        )

        manager = ModelManager(config)

        with patch.object(manager, '_list_remote_models', return_value=[]):
            success = manager.load_latest_model()

        assert success
        assert manager.is_model_available()

        info = manager.get_model_info()
        # Fallback model (random) doesn't set metadata like foundation does
        # The foundation model sets type='foundation'
        is_foundation = False
        if 'model_metadata' in info and info['model_metadata']:
             if info['model_metadata'].get('type') == 'foundation':
                 is_foundation = True

        assert not is_foundation
