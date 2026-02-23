# API Reference

This document provides a detailed reference for the core Python classes in the **Ulti_Argus** ecosystem.

---

## 🛡️ AegisDaemon

`Ulti_argus/src/argus_v/aegis/daemon.py`

The main service that orchestrates the Aegis shield runtime. It manages components like the Prediction Engine, Blacklist Manager, and Model Manager.

### Class: `AegisDaemon`

#### Methods

**`__init__(self, config_path: str)`**
*   **Description**: Initializes the Aegis daemon.
*   **Args**:
    *   `config_path` (str): Path to the configuration file (YAML).
*   **Raises**: `ServiceStartError` if configuration loading fails.

**`start(self) -> bool`**
*   **Description**: Starts the Aegis daemon service and its sub-components (Anonymizer, ModelManager, BlacklistManager, PredictionEngine, etc.).
*   **Returns**: `True` if started successfully, `False` otherwise.

**`stop(self, timeout: Optional[int] = None) -> bool`**
*   **Description**: Stops the Aegis daemon service gracefully.
*   **Args**:
    *   `timeout` (int, optional): Timeout in seconds for graceful shutdown. Defaults to config value.
*   **Returns**: `True` if stopped successfully.

**`get_health_status(self) -> Dict[str, Any]`**
*   **Description**: Returns a comprehensive health status of the daemon and its components.
*   **Returns**: A dictionary containing `overall_health`, `components_healthy`, and component-specific details.

**`get_status(self) -> Dict[str, Any]`**
*   **Description**: Returns detailed status including health, statistics, configuration, and active components.

**`emergency_stop(self, reason: str = "Manual emergency stop") -> bool`**
*   **Description**: Stops all enforcement actions immediately.
*   **Args**:
    *   `reason` (str): Reason for the emergency stop.

**`emergency_restore(self, reason: str = "Manual emergency restore") -> bool`**
*   **Description**: Restores normal operations after an emergency stop.

---

## 🔮 PredictionEngine

`Ulti_argus/src/argus_v/aegis/prediction_engine.py`

The core engine that processes flow data (from CSV or IPC), runs the Isolation Forest model, and makes enforcement decisions.

### Class: `PredictionEngine`

#### Methods

**`start(self) -> bool`**
*   **Description**: Starts the background polling and prediction threads.

**`stop(self, timeout: Optional[int] = None) -> bool`**
*   **Description**: Stops the prediction engine.

**`get_statistics(self) -> Dict[str, Any]`**
*   **Description**: Returns current statistics (flows processed, anomalies detected, enforcement actions, etc.).

**`force_process_file(self, csv_file: Path) -> bool`**
*   **Description**: Forces processing of a specific CSV file, useful for testing or manual intervention.
*   **Args**:
    *   `csv_file` (Path): Path to the CSV file.

---

## 🚫 BlacklistManager

`Ulti_argus/src/argus_v/aegis/blacklist_manager.py`

Manages the decentralized blacklist storage (SQLite/JSON) and handles enforcement (iptables/eBPF).

### Class: `BlacklistManager`

#### Methods

**`add_to_blacklist(self, ip_address: str, reason: str, source: str = "prediction", risk_level: str = "medium", ttl_hours: Optional[int] = None, enforce: bool = False, metadata: Optional[Dict[str, Any]] = None) -> bool`**
*   **Description**: Adds an IP address to the blacklist.
*   **Args**:
    *   `ip_address` (str): The IP to blacklist.
    *   `reason` (str): Reason for blacklisting.
    *   `source` (str): Source of the entry (e.g., "prediction", "manual").
    *   `risk_level` (str): Risk level ("low", "medium", "high", "critical").
    *   `ttl_hours` (int, optional): Time-to-live in hours.
    *   `enforce` (bool): Whether to enforce the ban immediately.

**`remove_from_blacklist(self, ip_address: str, source: str = "prediction") -> bool`**
*   **Description**: Removes an IP address from the blacklist (soft delete).
*   **Args**:
    *   `ip_address` (str): The IP to remove.
    *   `source` (str): Source of the entry to remove.

**`is_blacklisted(self, ip_address: str) -> bool`**
*   **Description**: Checks if an IP address is currently active in the blacklist.
*   **Returns**: `True` if blacklisted and active, `False` otherwise.

**`get_blacklist_entries(self, active_only: bool = True, risk_level: Optional[str] = None, source: Optional[str] = None, limit: Optional[int] = None) -> Iterator[Dict[str, Any]]`**
*   **Description**: Retrieves blacklist entries with optional filtering.
*   **Returns**: An iterator of dictionaries representing blacklist entries.

**`cleanup_expired_entries(self) -> int`**
*   **Description**: Marks expired entries as inactive in the database.
*   **Returns**: Number of entries cleaned up.

**`sync_with_firebase(self) -> bool`**
*   **Description**: Synchronizes the local blacklist with Firebase Storage (if configured).

---

## ⚡ KronosEnforcer

`Ulti_argus/src/argus_v/kronos/enforcer.py`

Wrapper around `bpftool` to manipulate the kernel eBPF `BLOCKLIST` map directly.

### Class: `KronosEnforcer`

#### Methods

**`__init__(self, map_name: str = "BLOCKLIST")`**
*   **Description**: Initializes the enforcer and attempts to locate the eBPF map ID.

**`block_ip(self, ip_address: str) -> bool`**
*   **Description**: Adds an IP to the eBPF map to drop packets from it at the XDP layer.
*   **Args**:
    *   `ip_address` (str): IPv4 address to block.

**`unblock_ip(self, ip_address: str) -> bool`**
*   **Description**: Removes an IP from the eBPF map.
*   **Args**:
    *   `ip_address` (str): IPv4 address to unblock.

---

## 🖥️ AegisCLI

`Ulti_argus/src/argus_v/aegis/cli.py`

Command-line interface for managing the Aegis service.

### Class: `AegisCLI`

#### Methods

**`run(self, args: Optional[list[str]] = None) -> int`**
*   **Description**: Parses arguments and executes the requested command (`start`, `stop`, `status`, `health`, etc.).
*   **Args**:
    *   `args` (list[str], optional): Command line arguments. Defaults to `sys.argv`.

---

## 📊 AegisDashboard (TUI)

`Ulti_argus/src/argus_v/aegis/tui.py`

A terminal-based user interface using `rich` to display live statistics and active blocks.

### Class: `AegisDashboard`

#### Methods

**`run(self)`**
*   **Description**: Starts the live UI loop, refreshing the display every second.
