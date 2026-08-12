from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

REPO = Path(__file__).resolve().parents[2]
ARTIFACT_SUFFIXES = {
    ".pkl",
    ".pickle",
    ".joblib",
    ".pt",
    ".pth",
    ".onnx",
    ".npz",
    ".npy",
    ".h5",
    ".hdf5",
    ".pcap",
    ".pcapng",
    ".etl",
}


def test_public_tree_contains_no_private_artifacts() -> None:
    found = [
        path.relative_to(REPO).as_posix()
        for path in REPO.rglob("*")
        if path.is_file()
        and ".git" not in path.parts
        and ".venv" not in path.parts
        and (
            path.suffix.lower() in ARTIFACT_SUFFIXES
            or path.name.endswith(".argus-baseline.json")
        )
    ]
    assert found == []


def test_only_supported_runtime_packages_are_published() -> None:
    package = REPO / "Ulti_argus" / "src" / "argus_v"
    published = {
        path.name for path in package.iterdir() if any(path.rglob("*.py"))
    }
    assert published == {"dpi", "oracle_core", "retina"}


def test_public_api_excludes_private_service_groups() -> None:
    from web.api.server import app

    paths = {route.path for route in app.routes}
    forbidden_prefixes = (
        "/api/pipeline",
        "/api/models",
        "/api/explain",
        "/api/enforce",
        "/api/learn",
        "/api/multimodal",
        "/api/data",
        "/api/investigate",
        "/api/deception",
    )
    assert not any(path.startswith(forbidden_prefixes) for path in paths)
    assert "/api/system" in paths
    assert "/api/detect/flows" in paths
    assert "/api/signatures/patterns" in paths


def test_unmatched_flow_is_unassessed_not_benign() -> None:
    from web.api.capture.analyzer import analyze_flow

    result = analyze_flow(
        {
            "flow_id": "public-boundary",
            "src_ip": "192.0.2.1",
            "dst_ip": "198.51.100.1",
            "src_port": 40000,
            "dst_port": 443,
            "protocol": "TCP",
            "packets_in": 1,
            "packets_out": 0,
            "bytes_in": 60,
            "bytes_out": 0,
            "duration": 0.0,
            "payloads": [],
        }
    )

    assert result["status"] == "UNASSESSED"
    assert result["route"] == "COMMUNITY_OBSERVE_ONLY"
    assert "score" not in result
    assert not any("model" in key.lower() for key in result)


def test_public_api_starts_and_reports_community_scope() -> None:
    from web.api.deps import API_KEY
    from web.api.server import app

    with TestClient(app) as client:
        response = client.get("/")
        assert response.status_code == 200
        assert "Argus Community API" in response.text
        assert "optional user-trained baseline" in response.text

        headers = {"X-API-Key": API_KEY}
        auth = client.post("/api/auth/verify", json={"token": API_KEY})
        assert auth.status_code == 200
        assert client.get("/api/system").status_code == 200

        system = client.get("/api/system", headers=headers)
        assert system.status_code == 200
        assert system.json()["components"]["baseline_model"]["status"] == "not_configured"

        flows = client.get("/api/detect/flows", headers=headers)
        assert flows.status_code == 200
        assert isinstance(flows.json(), list)

        patterns = client.get("/api/signatures/patterns")
        assert patterns.status_code == 200
