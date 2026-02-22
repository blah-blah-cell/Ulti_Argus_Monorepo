"""Terminal User Interface (TUI) for Aegis.

Uses the `rich` library to build a live-updating dashboard summarizing
the Aegis runtime state, statistics, and the active eBPF/iptables
blocklist.
"""

from __future__ import annotations

import argparse
import json
import logging
import sqlite3
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from rich.align import Align
    from rich.console import Console
    from rich.layout import Layout
    from rich.live import Live
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
except ImportError:
    print("Error: The 'rich' library is required for the TUI.")
    print("Run: pip install rich")
    sys.exit(1)

from .config import get_default_config_path, load_aegis_config

# Configure basic logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


class AegisDashboard:
    """Live-updating Terminal Dashboard for Aegis."""

    def __init__(self, config_path: str | None = None):
        """Initialize the dashboard.

        Args:
            config_path: Path to the Aegis configuration file.
        """
        self.console = Console()
        if config_path is None:
            config_path = str(get_default_config_path())

        try:
            self.config = load_aegis_config(config_path)
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            sys.exit(1)
        
        # Paths to poll
        self.stats_file = Path(self.config.stats_file)
        self.state_file = Path(self.config.state_file)

        # Correctly access enforcement config for blacklist db path
        self.blacklist_db = Path(self.config.enforcement.blacklist_db_path)

    def _read_stats(self) -> Dict[str, Any]:
        """Read the Aegis stats.json file safely."""
        try:
            if self.stats_file.exists():
                with open(self.stats_file, "r") as f:
                    return json.load(f)
        except Exception as e:
            logger.debug(f"Failed to read stats file: {e}")
        return {}

    def _read_engine_state(self) -> str:
        """Read the Aegis state.json file safely."""
        try:
            if self.state_file.exists():
                with open(self.state_file, "r") as f:
                    state = json.load(f)
                    return state.get("state", "UNKNOWN")
        except Exception as e:
            logger.debug(f"Failed to read state file: {e}")
        return "Not Running / Unknown"

    def _read_active_blocks(self, limit: int = 15) -> List[tuple]:
        """Read the latest active blocks from the SQLite DB."""
        if not self.blacklist_db.exists():
            return []

        try:
            with sqlite3.connect(self.blacklist_db) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT ip_address, reason, risk_level, source, created_at, hit_count
                    FROM blacklist
                    WHERE is_active = TRUE
                    ORDER BY created_at DESC
                    LIMIT ?
                """, (limit,))
                return cursor.fetchall()
        except Exception as e:
            logger.debug(f"Failed to read active blocks: {e}")
            return []

    def make_header(self) -> Panel:
        """Create the top header pane."""
        state = self._read_engine_state()
        color = "green" if state.upper() == "RUNNING" else "red"
        
        grid = Table.grid(expand=True)
        grid.add_column(justify="left", ratio=1)
        grid.add_column(justify="right")
        
        title = Text("Ulti_Argus Aegis - Live Dashboard", style="bold cyan")
        status = Text(f"Engine State: {state.upper()}", style=f"bold {color}")
        
        grid.add_row(title, status)
        return Panel(grid, style="cyan")

    def make_stats_panel(self) -> Panel:
        """Create the statistics pane."""
        stats = self._read_stats()
        
        table = Table(show_header=False, expand=True, box=None)
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="bold white")
        
        # Safe extraction
        total_flows = str(stats.get("total_flows_processed", 0))
        anomalies = str(stats.get("anomalies_detected", 0))
        predictions = str(stats.get("total_predictions_made", 0))
        blocks = str(stats.get("active_blacklist_entries", 0))
        
        uptime = stats.get("uptime_seconds", 0)
        
        # Convert uptime to H:M:S
        m, s = divmod(int(uptime), 60)
        h, m = divmod(m, 60)
        uptime_str = f"{h}h {m}m {s}s"

        table.add_row("Uptime (Daemon)", uptime_str)
        table.add_row("Total Flows Analyzed", total_flows)
        table.add_row("Total Predictions", predictions)
        table.add_row("Anomalies Caught", f"[red]{anomalies}[/red]")
        table.add_row("Active eBPF/OS Blocks", f"[yellow]{blocks}[/yellow]")
        
        return Panel(
            Align.center(table, vertical="middle"), 
            title="[bold]Real-Time Telemetry[/bold]", 
            border_style="blue"
        )

    def make_blocklist_table(self) -> Panel:
        """Create a table showing the currently active blocked IPs."""
        blocks = self._read_active_blocks()
        
        table = Table(
            expand=True, 
            show_lines=True, 
            header_style="bold magenta", 
            border_style="magenta"
        )
        table.add_column("IP Address", style="bold cyan", width=16)
        table.add_column("Risk", justify="center", width=10)
        table.add_column("Reason", style="white")
        table.add_column("Hits", justify="right", width=6)
        table.add_column("Blocked At", style="dim", width=20)
        
        for ip, reason, risk, source, created_at, hit_count in blocks:
            # Colorize risk
            risk_color = "yellow"
            if risk == "critical":
                risk_color = "bold red"
            elif risk == "high":
                risk_color = "red"
            
            # Format datetime
            try:
                dt = datetime.fromisoformat(created_at).strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                dt = str(created_at)

            table.add_row(
                ip,
                f"[{risk_color}]{risk.upper()}[/{risk_color}]",
                reason,
                str(hit_count),
                dt
            )
            
        if not blocks:
            table = Align.center(Text("No active blocks at this time.", style="dim italic"))

        return Panel(
            table, 
            title="[bold red]Active eBPF Enforcements (BLOCKLIST)[/bold red]", 
            border_style="red"
        )

    def generate_layout(self) -> Layout:
        """Build the complete Rich Layout grid."""
        layout = Layout()
        
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="main")
        )
        
        layout["main"].split_row(
            Layout(name="left_panel", ratio=1),
            Layout(name="right_panel", ratio=2)
        )
        
        layout["header"].update(self.make_header())
        layout["left_panel"].update(self.make_stats_panel())
        layout["right_panel"].update(self.make_blocklist_table())
        
        return layout

    def run(self):
        """Start the live UI loop."""
        print("Starting Aegis Live TUI...")
        
        try:
            with Live(self.generate_layout(), refresh_per_second=2, screen=True) as live:
                while True:
                    time.sleep(1.0) # Refresh every second
                    live.update(self.generate_layout())
        except KeyboardInterrupt:
            print("\nAegis TUI stopped.")
        except Exception as e:
            logger.error(f"TUI crashed: {e}")


def main():
    """CLI Entrypoint for argus-tui."""
    parser = argparse.ArgumentParser(description="Aegis Live TUI Dashboard")
    parser.add_argument("--config", help="Path to Aegis configuration file")
    args = parser.parse_args()

    dashboard = AegisDashboard(config_path=args.config)
    dashboard.run()


if __name__ == "__main__":
    main()
