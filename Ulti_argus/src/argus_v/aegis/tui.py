"""Terminal User Interface (TUI) for Aegis.

Uses the ``rich`` library to build a live-updating dashboard that shows
real-time telemetry, active eBPF blocklist entries, model / AI-pipeline
health, and a recent-threat feed.

Keybindings
-----------
q / Ctrl-C   Quit
r            Force refresh
h            Toggle help overlay
"""

from __future__ import annotations

import json
import os
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
    from rich.columns import Columns
    from rich import box
except ImportError:
    print("Error: The 'rich' library is required for the TUI.")
    print("Run: pip install rich")
    sys.exit(1)

from .config import get_default_config_path, load_aegis_config


# ── Sparkline helper ─────────────────────────────────────────────────────
_SPARK_CHARS = "▁▂▃▄▅▆▇█"


def _sparkline(values: List[float], width: int = 20) -> str:
    """Render a compact ASCII spark-line from *values*."""
    if not values:
        return "─" * width
    values = values[-width:]
    lo, hi = min(values), max(values)
    rng = hi - lo if hi != lo else 1
    return "".join(
        _SPARK_CHARS[min(int((v - lo) / rng * (len(_SPARK_CHARS) - 1)), len(_SPARK_CHARS) - 1)]
        for v in values
    )


# ── Dashboard ─────────────────────────────────────────────────────────────
class AegisDashboard:
    """Live-updating Terminal Dashboard for Aegis."""

    # Refresh cadence (seconds)
    REFRESH_INTERVAL = 1.0

    def __init__(self, config_path: str | None = None):
        self.console = Console()
        if config_path is None:
            config_path = str(get_default_config_path())
        self.config = load_aegis_config(config_path)

        # Paths to poll
        self.stats_file = Path(self.config.stats_file)
        self.blacklist_db = Path(self.config.enforcement.blacklist_db_path)
        self.state_file = Path(self.config.state_file)
        self.model_dir = Path(self.config.model.model_local_path)

        # Persistent DB connection
        self._conn: Optional[sqlite3.Connection] = None

        # Caching
        self._stats_cache: Dict[str, Any] = {}
        self._stats_mtime: float = 0.0
        self._state_cache: str = "OFFLINE"
        self._state_mtime: float = 0.0

        # Threat-rate history (rolling window for sparkline)
        self._anomaly_history: List[int] = []
        self._last_anomaly_count: int = 0

        # Help overlay toggle
        self._show_help: bool = False

        # Build reusable layout
        self.layout = self._build_layout()

    # ── Layout construction ───────────────────────────────────────────
    @staticmethod
    def _build_layout() -> Layout:
        root = Layout(name="root")
        root.split_column(
            Layout(name="header", size=3),
            Layout(name="body"),
            Layout(name="footer", size=3),
        )
        root["body"].split_row(
            Layout(name="left", ratio=2),
            Layout(name="right", ratio=3),
        )
        root["left"].split_column(
            Layout(name="telemetry", ratio=2),
            Layout(name="model_health", ratio=1),
        )
        root["right"].split_column(
            Layout(name="blocklist", ratio=3),
            Layout(name="threat_feed", ratio=1),
        )
        return root

    # ── Data readers ──────────────────────────────────────────────────
    def _get_db_connection(self) -> Optional[sqlite3.Connection]:
        if self._conn:
            return self._conn
        if self.blacklist_db.exists():
            try:
                self._conn = sqlite3.connect(
                    self.blacklist_db, check_same_thread=False
                )
                return self._conn
            except Exception:
                pass
        return None

    def _read_stats(self) -> Dict[str, Any]:
        try:
            if self.stats_file.exists():
                mtime = os.stat(self.stats_file).st_mtime
                if mtime != self._stats_mtime:
                    with open(self.stats_file, "r") as f:
                        self._stats_cache = json.load(f)
                        self._stats_mtime = mtime
                return self._stats_cache
        except Exception:
            pass
        return {}

    def _read_engine_state(self) -> str:
        try:
            if self.state_file.exists():
                mtime = os.stat(self.state_file).st_mtime
                if mtime != self._state_mtime:
                    with open(self.state_file, "r") as f:
                        state = json.load(f)
                        self._state_cache = state.get("state", "UNKNOWN")
                        self._state_mtime = mtime
                return self._state_cache
        except Exception:
            pass
        return "OFFLINE"

    def _read_active_blocks(self, limit: int = 15) -> List[tuple]:
        conn = self._get_db_connection()
        if not conn:
            return []
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT ip_address, reason, risk_level, source,
                       created_at, hit_count
                FROM blacklist
                WHERE is_active = TRUE
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (limit,),
            )
            return cursor.fetchall()
        except Exception:
            try:
                conn.close()
            except Exception:
                pass
            self._conn = None
            return []

    def _read_recent_threats(self, limit: int = 5) -> List[tuple]:
        """Read the most recent threat events from the blacklist DB."""
        conn = self._get_db_connection()
        if not conn:
            return []
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT ip_address, risk_level, reason, created_at
                FROM blacklist
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (limit,),
            )
            return cursor.fetchall()
        except Exception:
            return []

    def _detect_model_info(self) -> Dict[str, str]:
        """Detect which model file is loaded and its metadata."""
        info: Dict[str, str] = {
            "status": "No Models",
            "name": "—",
            "age": "—",
            "type": "—",
        }
        try:
            if not self.model_dir.exists():
                return info
            models = sorted(self.model_dir.glob("model_*.pkl"), reverse=True)
            if not models:
                return info
            latest = models[0]
            info["name"] = latest.stem
            info["status"] = "Loaded"
            info["type"] = "Isolation Forest"

            # Parse timestamp from filename: model_YYYYMMDD_HHMMSS.pkl
            ts_part = latest.stem.replace("model_", "")
            try:
                model_dt = datetime.strptime(ts_part, "%Y%m%d_%H%M%S")
                age = datetime.now() - model_dt
                if age.days > 0:
                    info["age"] = f"{age.days}d {age.seconds // 3600}h"
                else:
                    hours = age.seconds // 3600
                    mins = (age.seconds % 3600) // 60
                    info["age"] = f"{hours}h {mins}m"
            except ValueError:
                info["age"] = "unknown"
        except Exception:
            info["status"] = "Error"
        return info

    # ── Panel builders ────────────────────────────────────────────────
    def _make_header(self) -> Panel:
        state = self._read_engine_state()
        color = "green" if state.upper() == "RUNNING" else "yellow" if state.upper() in ("STARTING", "STOPPING") else "red"

        grid = Table.grid(expand=True)
        grid.add_column(justify="left", ratio=1)
        grid.add_column(justify="center", ratio=1)
        grid.add_column(justify="right")

        title = Text("◈ Ulti_Argus — Aegis Shield Dashboard", style="bold cyan")
        clock = Text(datetime.now().strftime("%Y-%m-%d  %H:%M:%S"), style="dim white")
        status = Text(f"● {state.upper()}", style=f"bold {color}")

        grid.add_row(title, clock, status)
        return Panel(grid, style="bright_cyan", box=box.HEAVY)

    def _make_telemetry(self) -> Panel:
        stats = self._read_stats()

        table = Table(show_header=False, expand=True, box=None, padding=(0, 1))
        table.add_column("Metric", style="cyan", ratio=2)
        table.add_column("Value", style="bold white", justify="right", ratio=1)

        total_flows = stats.get("total_flows_processed", 0)
        anomalies = stats.get("anomalies_detected", 0)
        predictions = stats.get("total_predictions_made", 0)
        blocks = stats.get("active_blacklist_entries", 0)
        uptime = stats.get("uptime_seconds", 0)

        # Track anomaly rate for sparkline
        if anomalies != self._last_anomaly_count:
            delta = anomalies - self._last_anomaly_count
            self._anomaly_history.append(max(0, delta))
            self._last_anomaly_count = anomalies
        else:
            self._anomaly_history.append(0)
        # Keep last 30 data-points
        self._anomaly_history = self._anomaly_history[-30:]

        # Uptime
        m, s = divmod(int(uptime), 60)
        h, m = divmod(m, 60)
        uptime_str = f"{h:02d}:{m:02d}:{s:02d}"

        # Detection rate
        det_rate = f"{anomalies / total_flows * 100:.1f}%" if total_flows > 0 else "—"

        table.add_row("⏱  Uptime", uptime_str)
        table.add_row("📊 Flows Analyzed", f"{total_flows:,}")
        table.add_row("🔮 Predictions", f"{predictions:,}")
        table.add_row("🚨 Anomalies", f"[red]{anomalies:,}[/red]")
        table.add_row("🛡  Active Blocks", f"[yellow]{blocks:,}[/yellow]")
        table.add_row("📈 Detection Rate", det_rate)
        table.add_row("")
        table.add_row("Threat Rate", f"[dim]{_sparkline(self._anomaly_history)}[/dim]")

        return Panel(
            Align.center(table, vertical="middle"),
            title="[bold]Real-Time Telemetry[/bold]",
            border_style="blue",
        )

    def _make_model_health(self) -> Panel:
        info = self._detect_model_info()

        table = Table(show_header=False, expand=True, box=None, padding=(0, 1))
        table.add_column("K", style="dim cyan", ratio=1)
        table.add_column("V", style="white", ratio=2)

        status_style = "green" if info["status"] == "Loaded" else "red"
        table.add_row("Status", f"[{status_style}]{info['status']}[/{status_style}]")
        table.add_row("Model", info["name"])
        table.add_row("Type", info["type"])
        table.add_row("Age", info["age"])

        return Panel(
            table,
            title="[bold]AI Pipeline[/bold]",
            border_style="magenta",
        )

    def _make_blocklist(self) -> Panel:
        blocks = self._read_active_blocks()

        table = Table(
            expand=True,
            show_lines=False,
            header_style="bold magenta",
            border_style="dim magenta",
            box=box.SIMPLE_HEAVY,
        )
        table.add_column("IP Address", style="bold cyan", width=16)
        table.add_column("Risk", justify="center", width=10)
        table.add_column("Reason", style="white", ratio=2)
        table.add_column("Hits", justify="right", width=6)
        table.add_column("Blocked At", style="dim", width=20)

        risk_colors = {
            "critical": "bold red",
            "high": "red",
            "medium": "yellow",
            "low": "dim green",
        }

        for ip, reason, risk, _source, created_at, hit_count in blocks:
            rc = risk_colors.get(risk, "yellow")
            try:
                dt = datetime.fromisoformat(created_at).strftime("%Y-%m-%d %H:%M")
            except Exception:
                dt = str(created_at)[:16]

            table.add_row(
                ip,
                f"[{rc}]{risk.upper()}[/{rc}]",
                reason[:40],
                str(hit_count),
                dt,
            )

        body: Any = table
        if not blocks:
            body = Align.center(
                Text("✓ No active blocks — all clear", style="bold green"),
                vertical="middle",
            )

        return Panel(
            body,
            title="[bold red]Active eBPF Enforcements[/bold red]",
            border_style="red",
        )

    def _make_threat_feed(self) -> Panel:
        threats = self._read_recent_threats()

        if not threats:
            body = Align.center(
                Text("No recent threat events", style="dim italic")
            )
        else:
            lines: List[Text] = []
            for ip, risk, reason, created_at in threats:
                try:
                    ts = datetime.fromisoformat(created_at).strftime("%H:%M:%S")
                except Exception:
                    ts = "??:??:??"
                icon = "🔴" if risk in ("critical", "high") else "🟡"
                lines.append(
                    Text.from_markup(
                        f"{icon} [dim]{ts}[/dim]  [bold]{ip}[/bold]  {reason[:30]}"
                    )
                )
            body = Align.left(Text("\n").join(lines))

        return Panel(
            body,
            title="[bold]Recent Threat Feed[/bold]",
            border_style="yellow",
        )

    def _make_footer(self) -> Panel:
        keys = Text.from_markup(
            "  [bold cyan]q[/bold cyan] Quit   "
            "[bold cyan]r[/bold cyan] Refresh   "
            "[bold cyan]h[/bold cyan] Help"
        )
        return Panel(keys, style="dim", box=box.SIMPLE)

    def _make_help_overlay(self) -> Panel:
        help_text = Text.from_markup(
            "[bold cyan]Aegis TUI — Keyboard Shortcuts[/bold cyan]\n\n"
            "[bold]q[/bold] / [bold]Ctrl-C[/bold]   Exit the dashboard\n"
            "[bold]r[/bold]               Force a data refresh\n"
            "[bold]h[/bold]               Toggle this help panel\n\n"
            "[dim]Data is polled from stats.json, state.json, and the\n"
            "blacklist SQLite database. Refresh rate: 1 Hz.[/dim]"
        )
        return Panel(
            Align.center(help_text, vertical="middle"),
            title="[bold]Help[/bold]",
            border_style="bright_cyan",
        )

    # ── Update cycle ──────────────────────────────────────────────────
    def _update_layout(self) -> Layout:
        self.layout["header"].update(self._make_header())
        self.layout["footer"].update(self._make_footer())

        if self._show_help:
            self.layout["left"].update(self._make_help_overlay())
            self.layout["right"].update(self._make_help_overlay())
        else:
            self.layout["telemetry"].update(self._make_telemetry())
            self.layout["model_health"].update(self._make_model_health())
            self.layout["blocklist"].update(self._make_blocklist())
            self.layout["threat_feed"].update(self._make_threat_feed())

        return self.layout

    # ── Main loop ─────────────────────────────────────────────────────
    def run(self) -> None:
        """Start the live TUI loop."""
        self.console.print("[bold cyan]Starting Aegis Live TUI...[/bold cyan]")

        # Initial render
        self._update_layout()

        with Live(
            self.layout,
            refresh_per_second=2,
            screen=True,
            console=self.console,
        ) as live:
            try:
                while True:
                    # Non-blocking key check (platform-dependent)
                    key = self._poll_key()
                    if key == "q":
                        break
                    elif key == "r":
                        pass  # falls through to refresh
                    elif key == "h":
                        self._show_help = not self._show_help

                    live.update(self._update_layout())
                    time.sleep(self.REFRESH_INTERVAL)
            except KeyboardInterrupt:
                pass

    @staticmethod
    def _poll_key() -> Optional[str]:
        """Non-blocking single-key read.  Returns ``None`` when no key pressed."""
        try:
            if sys.platform == "win32":
                import msvcrt

                if msvcrt.kbhit():
                    ch = msvcrt.getwch()
                    return ch.lower()
            else:
                import select
                import termios
                import tty

                old = termios.tcgetattr(sys.stdin)
                try:
                    tty.setcbreak(sys.stdin.fileno())
                    if select.select([sys.stdin], [], [], 0)[0]:
                        return sys.stdin.read(1).lower()
                finally:
                    termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old)
        except Exception:
            pass
        return None


# ── CLI entry-point ───────────────────────────────────────────────────────
def main():
    """CLI entrypoint for ``argus-tui``."""
    config_path = sys.argv[1] if len(sys.argv) > 1 else None
    dashboard = AegisDashboard(config_path=config_path)
    dashboard.run()


if __name__ == "__main__":
    main()
