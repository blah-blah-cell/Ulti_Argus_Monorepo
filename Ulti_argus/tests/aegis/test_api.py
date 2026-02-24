import os
import sys
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

# Ensure src is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../src")))

from argus_v.aegis.daemon import app


@pytest.fixture
def mock_daemon():
    daemon = MagicMock()
    daemon._components = {
        'blacklist_manager': MagicMock(),
        'feedback_manager': MagicMock(),
        'prediction_engine': MagicMock(),
    }
    daemon.get_health_status.return_value = {"overall_health": "healthy"}
    daemon._stats = {"test": "stats"}
    return daemon

@pytest.fixture
def client(mock_daemon):
    app.state.daemon = mock_daemon
    return TestClient(app)

def test_whitelist_ip(client, mock_daemon):
    mock_daemon._components['blacklist_manager'].remove_from_blacklist.return_value = True
    response = client.post("/api/whitelist/192.168.1.1")
    assert response.status_code == 200
    assert response.json() == {"message": "IP 192.168.1.1 whitelisted"}
    mock_daemon._components['blacklist_manager'].remove_from_blacklist.assert_called_with("192.168.1.1", source="manual")

def test_whitelist_ip_failure(client, mock_daemon):
    mock_daemon._components['blacklist_manager'].remove_from_blacklist.return_value = False
    response = client.post("/api/whitelist/192.168.1.1")
    assert response.status_code == 400

def test_blacklist_ip(client, mock_daemon):
    mock_daemon._components['blacklist_manager'].add_to_blacklist.return_value = True
    payload = {"reason": "bad IP", "risk_level": "high"}
    response = client.post("/api/blacklist/192.168.1.2", json=payload)
    assert response.status_code == 200
    assert response.json() == {"message": "IP 192.168.1.2 blacklisted"}
    mock_daemon._components['blacklist_manager'].add_to_blacklist.assert_called_with(
        ip_address="192.168.1.2",
        reason="bad IP",
        risk_level="high",
        ttl_hours=None,
        source="manual",
        enforce=True
    )

def test_blacklist_ip_defaults(client, mock_daemon):
    mock_daemon._components['blacklist_manager'].add_to_blacklist.return_value = True
    response = client.post("/api/blacklist/192.168.1.3", json={})
    assert response.status_code == 200
    mock_daemon._components['blacklist_manager'].add_to_blacklist.assert_called_with(
        ip_address="192.168.1.3",
        reason="Manual blacklist",
        risk_level="medium",
        ttl_hours=None,
        source="manual",
        enforce=True
    )

def test_retrain(client, mock_daemon):
    mock_daemon._components['feedback_manager'].trigger_retrain.return_value = True
    response = client.post("/api/retrain")
    assert response.status_code == 200
    assert response.json() == {"message": "Retraining triggered"}
    mock_daemon._components['feedback_manager'].trigger_retrain.assert_called_once()

def test_status(client, mock_daemon):
    response = client.get("/api/status")
    assert response.status_code == 200
    assert response.json() == {"overall_health": "healthy"}

def test_metrics(client, mock_daemon):
    mock_daemon._components['prediction_engine'].get_statistics.return_value = {"predictions": 100}
    response = client.get("/api/metrics")
    assert response.status_code == 200
    json_resp = response.json()
    assert json_resp["test"] == "stats"
    assert json_resp["prediction_engine"]["predictions"] == 100

def test_websocket(client, mock_daemon):
    mock_daemon._components['prediction_engine'].get_statistics.return_value = {}
    mock_daemon._components['blacklist_manager']._stats = {'active_entries': 5}

    with client.websocket_connect("/ws") as websocket:
        data = websocket.receive_json()
        assert "health" in data
        assert "stats" in data
        assert "prediction_stats" in data
        assert data["active_blocks"] == 5

def test_blacklist_list(client, mock_daemon):
    mock_daemon._components['blacklist_manager'].get_blacklist_entries.return_value = [{"ip_address": "1.2.3.4"}]
    response = client.get("/api/blacklist")
    assert response.status_code == 200
    assert response.json() == [{"ip_address": "1.2.3.4"}]
    mock_daemon._components['blacklist_manager'].get_blacklist_entries.assert_called_with(active_only=True, limit=15)
