"""Runtime entry points: packet callback and public accessors.

This module wires the scapy callback through the flow tracker, runs the
analyzer on completed flows, and exposes read-only views of the runtime
state (results, stats, pattern matches).
"""
from __future__ import annotations

from web.api.capture import bootstrap, state
from web.api.capture.analyzer import analyze_flow
from web.api.capture.constants import MAX_RESULTS
from web.api.capture.packet import extract_packet


def packet_callback(pkt):
    """Called for each captured packet."""
    info = extract_packet(pkt)
    if not info:
        return

    state.stats["packets"] += 1
    state.stats["bytes"] += info.get("length", 0)
    state.stats["layer0_captured"] += 1

    completed_list = state.tracker.update(info)
    for completed in completed_list:
        state.stats["flows"] += 1
        result = analyze_flow(completed)

        with state.results_lock:
            state.results.append(result)
            if len(state.results) > MAX_RESULTS:
                state.results.pop(0)


def flush_tracker():
    """Flush all flows in the tracker and analyze them."""
    completed_list = state.tracker.flush()
    for completed in completed_list:
        state.stats["flows"] += 1
        result = analyze_flow(completed)

        with state.results_lock:
            state.results.append(result)
            if len(state.results) > MAX_RESULTS:
                state.results.pop(0)


def get_results(limit: int = 50) -> list[dict]:
    with state.results_lock:
        return list(state.results[-limit:])


def get_flow_by_id(flow_id: str) -> dict | None:
    """Get a specific flow by ID."""
    with state.results_lock:
        for r in state.results:
            if r.get("flow_id") == flow_id:
                return r
    return None


def get_stats() -> dict:
    pattern_stats = bootstrap.pattern_engine.get_stats()
    if bootstrap.baseline_model is not None:
        baseline = {
            "status": "loaded",
            "model_id": bootstrap.baseline_model.model_id,
            "trained_samples": bootstrap.baseline_model.trained_samples,
        }
    elif bootstrap.baseline_error:
        baseline = {"status": "rejected", "error": bootstrap.baseline_error}
    else:
        baseline = {"status": "not_configured"}
    return {
        **state.stats,
        "active_flows": state.tracker.active_count(),
        "baseline_model": baseline,
        "pattern_engine": pattern_stats,
        "feature_vector_size": bootstrap.feature_vector.vector_size,
    }


def get_pattern_matches(limit: int = 50) -> list[dict]:
    """Get recent pattern matches."""
    return bootstrap.pattern_engine.get_recent_matches(limit)
