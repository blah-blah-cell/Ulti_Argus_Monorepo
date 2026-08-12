"""Convert a completed real flow into a Community observation result."""
from __future__ import annotations

from typing import Dict

from web.api.capture import bootstrap, state
from web.api.capture.dpi import dpi_extract_features
from web.api.capture.inference import build_observation


def analyze_flow(flow: Dict) -> Dict:
    """Analyze observed properties without inventing a model verdict."""
    stats = state.stats

    # Layer 0 DPI summary
    dpi_apps = list(
        set(r.get("app_id", "Unknown") for r in flow.get("dpi_results", []))
    )
    dpi_app = dpi_apps[0] if dpi_apps else "Unknown"
    if dpi_app != "Unknown":
        stats["layer0_dpi_identified"] += 1

    pattern_matches = flow.get("pattern_matches", [])

    # Run pattern engine on DPI results
    dpi_features = {}
    if flow.get("payloads"):
        dpi_features = dpi_extract_features(flow["payloads"][0])

    # Build a DPIResult-shaped adapter over the existing flow so the
    # pattern engine can match against payload/transport/protocol features
    # without us needing to re-run the full DPI pipeline here.
    wf = flow.get("wireshark_features") or {}
    
    # Safely convert integer values
    def safe_int(val, default=0):
        try:
            if isinstance(val, str) and val.startswith("0x"):
                return int(val, 16)
            return int(val) if val is not None and val != "" else default
        except Exception:
            return default

    # Parse TCP flags only if it's TCP protocol and tcp_flags is present in wireshark_features
    has_tcp_flags = (flow.get("protocol") == "TCP" or wf.get("tcp_flags") is not None) and "tcp_flags" in wf
    tcp_flags_val = safe_int(wf.get("tcp_flags"), 0) if has_tcp_flags else None

    synthesized_dpi_view = type(
        "DPIResult",
        (),
        {
            "app_protocol": dpi_app,
            "pattern_matches": [],
            "payload": type(
                "P",
                (),
                {
                    "entropy": dpi_features.get("entropy", 0),
                    "payload_size": sum(len(p) for p in flow.get("payloads", [])),
                    "printable_ratio": dpi_features.get("printable_ratio", 0),
                    "unique_bytes": dpi_features.get("unique_bytes", 0),
                    "has_pe_magic": False,
                    "has_elf_magic": False,
                    "has_base64": dpi_features.get("printable_ratio", 0) > 0.9 or bool(wf.get("has_base64")),
                    "md5": "",
                    "sha256": "",
                    "byte_histogram": [0.0] * 256,
                    "bigram_entropy": 0.0,
                    "trigram_entropy": 0.0,
                    "null_bytes": 0,
                    "high_bytes": 0,
                    "max_freq": 0.0,
                    "has_hex_encoded": False,
                },
            )(),
            "http": type(
                "H",
                (),
                {
                    "method": wf.get("http_method", ""),
                    "uri": wf.get("http_uri", ""),
                    "host": wf.get("http_host", ""),
                    "user_agent": wf.get("http_ua", ""),
                    "referer": "",
                    "content_type": "",
                    "accept_language": "",
                    "response_code": safe_int(wf.get("http_code")),
                    "response_reason": "",
                    "request_size": 0,
                    "response_size": 0,
                    "uri_length": len(wf.get("http_uri", "")),
                    "header_count": 0,
                    "has_suspicious_useragent": any(ua in wf.get("http_ua", "").lower() for ua in ["sqlmap", "nikto", "nmap"]) if wf.get("http_ua") else False,
                },
            )(),
            "tls": type(
                "T",
                (),
                {
                    "tls_version": wf.get("tls_version", ""),
                    "tls_version_int": 0,
                    "cipher_suite": wf.get("tls_cipher", ""),
                    "cipher_suite_id": 0,
                    "is_weak_cipher": False,
                    "server_name": "",
                    "cert_issuer": "",
                    "cert_subject": "",
                    "cert_serial": "",
                    "cert_not_before": "",
                    "cert_not_after": "",
                    "cert_is_expired": False,
                    "cert_is_self_signed": False,
                    "cert_key_size": 0,
                    "cert_san": [],
                    "ja3_hash": "",
                    "ja3_string": "",
                    "ja3s_hash": "",
                    "ja3s_string": "",
                    "ja3_malware_family": "",
                },
            )(),
            "dns": type(
                "D",
                (),
                {
                    "query_name": wf.get("dns_query", ""),
                    "query_type": 0,
                    "query_type_name": wf.get("dns_type", ""),
                    "query_class": 0,
                    "is_response": bool(wf.get("dns_rcode")),
                    "response_code": safe_int(wf.get("dns_rcode")),
                    "answer_count": 0,
                    "authority_count": 0,
                    "additional_count": 0,
                    "query_name_length": len(wf.get("dns_query", "")),
                    "subdomain_count": len(wf.get("dns_query", "").split(".")) - 1 if wf.get("dns_query") else 0,
                    "is_txt_query": wf.get("dns_type") == "TXT",
                    "is_null_query": False,
                    "is_nxdomain": wf.get("dns_rcode") == "3",
                    "query_entropy": 0.0,
                    "has_long_subdomain": len(wf.get("dns_query", "")) > 50,
                    "has_high_entropy_subdomain": False,
                    "has_base64_subdomain": False,
                },
            )(),
            "transport": type(
                "Tr",
                (),
                {
                    "src_port": safe_int(wf.get("tcp_sport") or wf.get("udp_sport"), flow.get("src_port", 0)),
                    "dst_port": safe_int(wf.get("tcp_dport") or wf.get("udp_dport"), flow.get("dst_port", 0)),
                    "protocol": flow.get("protocol", "OTHER"),
                    "tcp_flags": tcp_flags_val or 0,
                    "tcp_window": safe_int(wf.get("tcp_window")),
                    "is_syn": bool(tcp_flags_val & 0x02) if has_tcp_flags else False,
                    "is_syn_ack": bool((tcp_flags_val & 0x02) and (tcp_flags_val & 0x10)) if has_tcp_flags else False,
                    "is_fin": bool(tcp_flags_val & 0x01) if has_tcp_flags else False,
                    "is_rst": bool(tcp_flags_val & 0x04) if has_tcp_flags else False,
                    "is_xmas": bool((tcp_flags_val & 0x01) and (tcp_flags_val & 0x08) and (tcp_flags_val & 0x20)) if has_tcp_flags else False,
                    "is_null": (tcp_flags_val == 0) if has_tcp_flags else False,
                    "is_ack": bool(tcp_flags_val & 0x10) if has_tcp_flags else False,
                    "is_psh": bool(tcp_flags_val & 0x08) if has_tcp_flags else False,
                    "is_urg": bool(tcp_flags_val & 0x20) if has_tcp_flags else False,
                },
            )(),
            "network": type(
                "N",
                (),
                {
                    "ip_flags_df": bool(wf.get("ip_flags_df")),
                    "ip_flags_mf": bool(wf.get("ip_flags_mf")),
                    "ttl": safe_int(wf.get("ttl"), 64),
                    "ip_total_length": safe_int(wf.get("ip_total_length")),
                },
            )(),
        },
    )()

    engine_matches = bootstrap.pattern_engine.match(synthesized_dpi_view)
    if engine_matches:
        for m in engine_matches:
            pattern_matches.append(
                {
                    "type": m.pattern_name,
                    "severity": m.severity,
                    "pattern": f"{m.pattern_name} (confidence: {m.confidence})",
                }
            )
        stats["pattern_matches"] += len(engine_matches)

    # Filter pattern matches to eliminate false positives on normal TCP SYN handshakes/timeouts
    valid_patterns = []
    for m in pattern_matches:
        p_name = m.get("type", "")
        # Apply safety volume thresholds for flow-level flood/scan rules
        if p_name == "syn_flood" and flow.get("tcp_syn_count", 0) <= 20:
            continue
        if p_name == "rst_flood" and flow.get("tcp_rst_count", 0) <= 20:
            continue
        if p_name == "port_scan" and flow.get("tcp_syn_count", 0) <= 5:
            continue
        if p_name == "null_scan" and flow.get("tcp_null_count", 0) <= 5:
            continue
        if p_name == "xmas_scan" and flow.get("tcp_xmas_count", 0) <= 5:
            continue
            
        valid_patterns.append(m)
        
    pattern_matches = valid_patterns

    if pattern_matches:
        stats["layer0_patterns_found"] += len(pattern_matches)

    observation = build_observation(flow, dpi_app, pattern_matches)
    model = bootstrap.baseline_model
    if model is None:
        return observation

    score = model.predict_score(observation)
    observation["baseline_score"] = round(score, 6)
    observation["route"] = "COMMUNITY_BASELINE"
    observation["decision_provenance"] = {
        "detector": "user_trained_logistic_baseline",
        "trained_model": True,
        "model_id": model.model_id,
        "feature_schema_version": "argus.flow-baseline.v1",
        "threshold": model.threshold,
        "decision_time": "online_flow_close",
    }
    if score >= model.threshold:
        observation["status"] = "SUSPICIOUS"
        observation["layer"] = "SIGNATURES+BASELINE" if pattern_matches else "BASELINE"
    return observation
