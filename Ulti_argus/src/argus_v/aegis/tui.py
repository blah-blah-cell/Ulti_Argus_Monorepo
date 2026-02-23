"""Terminal User Interface (TUI) for Aegis.

Uses the `textual` library to build a live-updating interactive command center.
"""

from __future__ import annotations

import asyncio
import json
import sys
from typing import Any, Dict, List

import httpx
from rich.table import Table
from rich.text import Text
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Header, Footer, Static, DataTable, Input, Log, Label
from textual.binding import Binding

class StatsPanel(Static):
    """Panel displaying real-time statistics."""

    def update_stats(self, stats: Dict[str, Any], health: Dict[str, Any]):
        table = Table(show_header=False, expand=True, box=None)
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="bold white")
        
        # Safe extraction
        total_flows = str(stats.get("total_flows_processed", 0))
        anomalies = str(stats.get("anomalies_detected", 0))
        predictions = str(stats.get("total_predictions_made", 0))
        
        service_info = health.get("service_info", {})
        uptime = service_info.get("uptime_seconds", 0)
        
        # Convert uptime to H:M:S
        m, s = divmod(int(uptime), 60)
        h, m = divmod(m, 60)
        uptime_str = f"{h}h {m}m {s}s"

        table.add_row("Uptime (Daemon)", uptime_str)
        table.add_row("Total Flows Analyzed", total_flows)
        table.add_row("Total Predictions", predictions)
        table.add_row("Anomalies Caught", f"[red]{anomalies}[/red]")
        
        self.update(table)

class ModelMetricsPanel(Static):
    """Panel displaying model performance metrics."""

    def update_metrics(self, stats: Dict[str, Any]):
        table = Table(show_header=False, expand=True, box=None)
        table.add_column("Metric", style="magenta")
        table.add_column("Value", style="bold green")

        # Mock metrics if not present, or extract from prediction_stats
        prediction_stats = stats.get("prediction_stats", {})
        
        latency = prediction_stats.get("avg_inference_latency_ms", 0.0)
        accuracy = "N/A" # Live accuracy is hard
        fpr = "N/A" # False Positive Rate

        table.add_row("Inference Latency", f"{latency:.2f} ms")
        table.add_row("Model Accuracy (Est)", accuracy)
        table.add_row("False Positive Rate", fpr)
        table.add_row("Active Model", stats.get("model_info", {}).get("model_type", "Unknown"))
        
        self.update(table)

class ActiveBlocksPanel(DataTable):
    """Panel displaying active blocks."""

    def on_mount(self) -> None:
        self.cursor_type = "row"
        self.zebra_stripes = True
        self.border_title = "Active eBPF Enforcements (BLOCKLIST)"
        self.add_columns("IP Address", "Risk", "Reason", "Hits", "Blocked At")

    def update_blocks(self, entries: List[Dict[str, Any]]):
        self.clear()
        for entry in entries:
            ip = entry.get('ip_address', 'Unknown')
            risk = entry.get('risk_level', 'medium')
            reason = entry.get('reason', 'N/A')
            hits = str(entry.get('hit_count', 0))
            created = str(entry.get('created_at', ''))

            # Formatting logic
            risk_styled = Text(risk.upper())
            if risk == "critical":
                risk_styled.stylize("bold red")
            elif risk == "high":
                risk_styled.stylize("red")
            elif risk == "medium":
                risk_styled.stylize("yellow")

            self.add_row(ip, risk_styled, reason, hits, created)

class AegisApp(App):
    CSS = """
    Screen {
        layout: vertical;
    }

    Header {
        dock: top;
    }

    Footer {
        dock: bottom;
    }

    Input {
        dock: bottom;
        margin: 0 0 1 0;
    }

    #main-container {
        layout: vertical;
        height: 1fr;
    }

    #top-row {
        layout: horizontal;
        height: 1fr;
    }

    StatsPanel {
        width: 1fr;
        border: solid blue;
        height: 100%;
    }

    ModelMetricsPanel {
        width: 1fr;
        border: solid magenta;
        height: 100%;
    }

    ActiveBlocksPanel {
        height: 2fr;
        border: solid red;
    }

    Log {
        height: 10;
        border: solid green;
        dock: bottom;
    }
    """

    BINDINGS = [("q", "quit", "Quit")]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Container(
            Horizontal(
                StatsPanel(id="stats-panel"),
                ModelMetricsPanel(id="metrics-panel"),
                id="top-row"
            ),
            ActiveBlocksPanel(id="blocks-panel"),
            id="main-container"
        )
        yield Log(id="log")
        yield Input(placeholder="Enter command (:block <ip>, :whitelist <ip>, :retrain, :status)...", id="command-input")
        yield Footer()

    async def on_mount(self) -> None:
        self.log_widget = self.query_one(Log)
        self.stats_panel = self.query_one(StatsPanel)
        self.metrics_panel = self.query_one(ModelMetricsPanel)
        self.blocks_panel = self.query_one(ActiveBlocksPanel)

        self.log_widget.write("Welcome to Aegis Command Center.")
        self.log_widget.write("Connecting to daemon...")

        # Start workers
        self.run_worker(self.websocket_worker(), exclusive=True)
        self.run_worker(self.blocks_worker(), exclusive=True)

    async def websocket_worker(self):
        import websockets
        uri = "ws://localhost:8081/ws"
        while True:
            try:
                async with websockets.connect(uri) as websocket:
                    self.log_widget.write("Connected to daemon (WebSocket).")
                    while True:
                        message = await websocket.recv()
                        data = json.loads(message)
                        self.call_from_thread(self.update_ui, data)
            except Exception as e:
                # self.log_widget.write(f"WS Connection lost: {e}. Retrying in 5s...")
                await asyncio.sleep(5)

    async def blocks_worker(self):
        base_url = "http://localhost:8081/api"
        async with httpx.AsyncClient() as client:
            while True:
                try:
                    response = await client.get(f"{base_url}/blacklist", params={"limit": 50})
                    if response.status_code == 200:
                        entries = response.json()
                        self.call_from_thread(self.blocks_panel.update_blocks, entries)
                except Exception:
                    pass
                await asyncio.sleep(2)

    def update_ui(self, data: Dict[str, Any]):
        stats = data.get("stats", {})
        health = data.get("health", {})
        
        self.stats_panel.update_stats(stats, health)
        self.metrics_panel.update_metrics(data)

    async def on_input_submitted(self, message: Input.Submitted) -> None:
        command = message.value.strip()
        message.input.value = ""

        if not command:
            return

        self.log_widget.write(f"> {command}")
        await self.process_command(command)

    async def process_command(self, command: str):
        parts = command.split()
        cmd = parts[0].lower()
        args = parts[1:]

        base_url = "http://localhost:8081/api"

        async with httpx.AsyncClient() as client:
            try:
                if cmd == ":block" and args:
                    ip = args[0]
                    payload = {"reason": "Manual TUI block", "risk_level": "medium"}
                    response = await client.post(f"{base_url}/blacklist/{ip}", json=payload)
                    if response.status_code == 200:
                        self.log_widget.write(f"Success: {response.json()}")
                    else:
                        self.log_widget.write(f"Error: {response.status_code} - {response.text}")
                    # Trigger immediate refresh of blocks
                    await self.blocks_worker_once(client, base_url)

                elif cmd == ":whitelist" and args:
                    ip = args[0]
                    response = await client.post(f"{base_url}/whitelist/{ip}")
                    if response.status_code == 200:
                        self.log_widget.write(f"Success: {response.json()}")
                    else:
                        self.log_widget.write(f"Error: {response.status_code} - {response.text}")
                    await self.blocks_worker_once(client, base_url)

                elif cmd == ":retrain":
                    response = await client.post(f"{base_url}/retrain")
                    if response.status_code == 200:
                        self.log_widget.write(f"Success: {response.json()}")
                    else:
                        self.log_widget.write(f"Error: {response.status_code} - {response.text}")

                elif cmd == ":status":
                    response = await client.get(f"{base_url}/status")
                    if response.status_code == 200:
                        self.log_widget.write(f"Status: {json.dumps(response.json(), indent=2)}")
                    else:
                        self.log_widget.write(f"Error: {response.status_code} - {response.text}")

                elif cmd == ":quit":
                    self.exit()

                else:
                    self.log_widget.write(f"Unknown command: {cmd}")

            except Exception as e:
                self.log_widget.write(f"Error executing command: {e}")

    async def blocks_worker_once(self, client, base_url):
        try:
            response = await client.get(f"{base_url}/blacklist", params={"limit": 50})
            if response.status_code == 200:
                entries = response.json()
                self.call_from_thread(self.blocks_panel.update_blocks, entries)
        except Exception:
            pass

def main():
    app = AegisApp()
    app.run()

if __name__ == "__main__":
    main()
