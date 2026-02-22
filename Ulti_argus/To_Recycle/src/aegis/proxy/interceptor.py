from mitmproxy import http
from mitmproxy import ctx
import logging
import sys
import os
import requests
import threading

# Ensure src is in path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../")))

from src.mnemosyne.inference import analyze_payload
from src.argus_plugins.manager import plugin_manager 

ANOMALY_THRESHOLD = 0.5 

def report_to_dashboard(method, host, path, score, plugin_alerts):
    def _send():
        try:
            is_threat = score > ANOMALY_THRESHOLD or len(plugin_alerts) > 0
            payload = {
                "type": "BLOCK" if is_threat else "VERIFIED",
                "desc": f"{method} {host}{path}",
                "score": float(score)
            }
            # Use a slightly longer timeout for the background thread
            requests.post("http://127.0.0.1:8000/ingest", json=payload, timeout=2.0)
        except Exception as e:
            # Silently fail in background to avoid spamming proxy logs
            pass
            
    # Fire and forget
    threading.Thread(target=_send, daemon=True).start()

class ArgusInterceptor:
    def __init__(self):
        # Discover plugins early
        plugin_manager.discover_and_load()

    def request(self, flow: http.HTTPFlow):
        host = flow.request.pretty_host
        method = flow.request.method
        path = flow.request.path
        content = flow.request.content
        
        score = 0.0
        plugin_alerts = []
        if content:
            score = analyze_payload(content)
            results = plugin_manager.run_on_payload(content)
            plugin_alerts = list(results.keys())
            
            # Sync report for debugging
            report_to_dashboard(method, host, path, score, plugin_alerts)
            
            if score > ANOMALY_THRESHOLD:
                ctx.log.warn(f"[AEGIS] BLOCKING Malicious Request to {host} (Score: {score:.4f})")
                flow.kill()

    def response(self, flow: http.HTTPFlow):
        content = flow.response.content
        if content:
             score = analyze_payload(content)
             if score > ANOMALY_THRESHOLD:
                 ctx.log.warn(f"[AEGIS] BLOCKING Malicious Response from {flow.request.pretty_host}")
                 flow.kill()

addons = [
    ArgusInterceptor()
]
