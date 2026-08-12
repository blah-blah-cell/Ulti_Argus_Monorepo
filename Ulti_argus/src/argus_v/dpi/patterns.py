"""Pattern-Based Detection Engine.

Rule-based pattern matching that runs alongside IF and CNN models.
Patterns are loadable from YAML/JSON config files.

Each pattern has:
- name: identifier
- description: what it detects
- severity: low, medium, high, critical
- conditions: list of feature conditions (AND/OR logic)
- action: log, alert, block
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from ..oracle_core.logging import log_event
from . import DPIResult, dpi_result_to_dict

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
#  Pattern Definition
# ═══════════════════════════════════════════════════════════════════════════════


@dataclass
class PatternCondition:
    """A single condition in a pattern rule."""

    feature: str  # Feature name (e.g., "syn_count", "entropy")
    operator: str  # ==, !=, >, <, >=, <=, contains, regex
    value: Any  # Threshold value
    window: Optional[float] = None  # Time window in seconds (for rate conditions)


@dataclass
class PatternRule:
    """A detection pattern."""

    name: str
    description: str
    severity: str  # low, medium, high, critical
    conditions: List[PatternCondition]
    logic: str = "AND"  # AND or OR
    action: str = "alert"  # log, alert, block
    enabled: bool = True
    threshold_count: int = 1  # How many conditions must match (for compound rules)


@dataclass
class PatternMatch:
    """Result of a pattern match."""

    pattern_name: str
    severity: str
    confidence: float  # 0.0 to 1.0
    matched_conditions: List[str]
    action: str
    timestamp: float = field(default_factory=time.time)
    details: Dict[str, Any] = field(default_factory=dict)


# ═══════════════════════════════════════════════════════════════════════════════
#  Built-in Patterns
# ═══════════════════════════════════════════════════════════════════════════════


BUILTIN_PATTERNS: List[Dict] = [
    {
        "name": "syn_flood",
        "description": "Detect SYN flood attacks",
        "severity": "critical",
        "logic": "AND",
        "action": "block",
        "conditions": [
            {"feature": "is_syn", "operator": "==", "value": True},
            {"feature": "is_ack", "operator": "==", "value": False},
        ],
    },
    {
        "name": "port_scan",
        "description": "Detect port scanning activity",
        "severity": "high",
        "logic": "AND",
        "action": "alert",
        "conditions": [
            {"feature": "is_syn", "operator": "==", "value": True},
            {"feature": "payload_size", "operator": "<", "value": 100},
        ],
    },
    {
        "name": "xmas_scan",
        "description": "Detect XMAS scan (FIN+PSH+URG)",
        "severity": "high",
        "logic": "AND",
        "action": "alert",
        "conditions": [
            {"feature": "is_xmas", "operator": "==", "value": True},
        ],
    },
    {
        "name": "null_scan",
        "description": "Detect NULL scan (no TCP flags)",
        "severity": "high",
        "logic": "AND",
        "action": "alert",
        "conditions": [
            {"feature": "is_null", "operator": "==", "value": True},
        ],
    },
    {
        "name": "dns_tunneling",
        "description": "Detect DNS tunneling attempts",
        "severity": "high",
        "logic": "OR",
        "action": "alert",
        "conditions": [
            {"feature": "dns_tunneling", "operator": "==", "value": True},
            {"feature": "dns_type", "operator": "==", "value": "TXT"},
        ],
    },
    {
        "name": "sql_injection",
        "description": "Detect SQL injection attempts",
        "severity": "critical",
        "logic": "OR",
        "action": "block",
        "conditions": [
            {
                "feature": "pattern_matches",
                "operator": "contains",
                "value": "SQL Injection",
            },
        ],
    },
    {
        "name": "xss_attack",
        "description": "Detect XSS attack patterns",
        "severity": "high",
        "logic": "OR",
        "action": "block",
        "conditions": [
            {"feature": "pattern_matches", "operator": "contains", "value": "XSS"},
        ],
    },
    {
        "name": "command_injection",
        "description": "Detect command injection attempts",
        "severity": "critical",
        "logic": "OR",
        "action": "block",
        "conditions": [
            {
                "feature": "pattern_matches",
                "operator": "contains",
                "value": "Command Injection",
            },
        ],
    },
    {
        "name": "path_traversal",
        "description": "Detect path traversal attempts",
        "severity": "high",
        "logic": "OR",
        "action": "alert",
        "conditions": [
            {
                "feature": "pattern_matches",
                "operator": "contains",
                "value": "Path Traversal",
            },
        ],
    },
    {
        "name": "high_entropy_payload",
        "description": "Detect high entropy payloads (encrypted/compressed)",
        "severity": "medium",
        "logic": "AND",
        "action": "alert",
        "conditions": [
            {"feature": "entropy", "operator": ">", "value": 7.5},
            {"feature": "payload_size", "operator": ">", "value": 512},
        ],
    },
    {
        "name": "suspicious_useragent",
        "description": "Detect suspicious User-Agent strings",
        "severity": "medium",
        "logic": "AND",
        "action": "alert",
        "conditions": [
            {"feature": "http_suspicious_ua", "operator": "==", "value": True},
        ],
    },
    {
        "name": "long_url",
        "description": "Detect unusually long URLs",
        "severity": "medium",
        "logic": "AND",
        "action": "alert",
        "conditions": [
            {"feature": "http_uri_length", "operator": ">", "value": 2048},
        ],
    },
    {
        "name": "tls_weak_cipher",
        "description": "Detect weak TLS cipher suites",
        "severity": "high",
        "logic": "AND",
        "action": "alert",
        "conditions": [
            {"feature": "tls_weak_cipher", "operator": "==", "value": True},
        ],
    },
    {
        "name": "known_malware_ja3",
        "description": "Detect known malware JA3 fingerprints",
        "severity": "critical",
        "logic": "AND",
        "action": "block",
        "conditions": [
            {"feature": "ja3_malware", "operator": "!=", "value": ""},
        ],
    },
    {
        "name": "pe_executable_in_traffic",
        "description": "Detect PE/ELF executables in network traffic",
        "severity": "critical",
        "logic": "OR",
        "action": "block",
        "conditions": [
            {"feature": "has_pe_magic", "operator": "==", "value": True},
            {"feature": "has_elf_magic", "operator": "==", "value": True},
        ],
    },
    {
        "name": "data_exfiltration",
        "description": "Detect potential data exfiltration",
        "severity": "high",
        "logic": "AND",
        "action": "alert",
        "conditions": [
            {"feature": "entropy", "operator": ">", "value": 7.0},
            {"feature": "payload_size", "operator": ">", "value": 10000},
            {"feature": "dst_port", "operator": "not_in", "value": [80, 443, 53]},
        ],
    },
    {
        "name": "nxdomain_flood",
        "description": "Detect DNS NXDOMAIN flood",
        "severity": "medium",
        "logic": "AND",
        "action": "alert",
        "conditions": [
            {"feature": "dns_nxdomain", "operator": "==", "value": True},
        ],
    },
    {
        "name": "base64_payload",
        "description": "Detect base64 encoded payloads",
        "severity": "low",
        "logic": "AND",
        "action": "log",
        "conditions": [
            {"feature": "has_base64", "operator": "==", "value": True},
            {"feature": "payload_size", "operator": ">", "value": 100},
        ],
    },
    {
        "name": "http_500_errors",
        "description": "Detect HTTP 500 errors (potential exploitation)",
        "severity": "medium",
        "logic": "AND",
        "action": "alert",
        "conditions": [
            {"feature": "http_response_code", "operator": ">=", "value": 500},
        ],
    },
    {
        "name": "rst_flood",
        "description": "Detect RST flood attacks",
        "severity": "high",
        "logic": "AND",
        "action": "block",
        "conditions": [
            {"feature": "is_rst", "operator": "==", "value": True},
            {"feature": "payload_size", "operator": "==", "value": 0},
        ],
    },
]


# ═══════════════════════════════════════════════════════════════════════════════
#  Pattern Engine
# ═══════════════════════════════════════════════════════════════════════════════


class PatternEngine:
    """Rule-based pattern detection engine.

    Matches DPI features against a set of rules to detect threats.
    Supports loading patterns from YAML/JSON config files.
    """

    def __init__(self, config_path: Optional[str] = None):
        self.patterns: List[PatternRule] = []
        self._match_history: List[PatternMatch] = []
        self._max_history = 1000

        # Load built-in patterns
        self._load_builtin_patterns()

        # Load external config if provided
        if config_path:
            self.load_config(config_path)

        log_event(
            logger,
            "pattern_engine_initialized",
            level="info",
            patterns=len(self.patterns),
        )

    def _load_builtin_patterns(self) -> None:
        """Load built-in detection patterns."""
        for p in BUILTIN_PATTERNS:
            conditions = []
            for c in p.get("conditions", []):
                conditions.append(
                    PatternCondition(
                        feature=c["feature"],
                        operator=c["operator"],
                        value=c["value"],
                        window=c.get("window"),
                    )
                )
            self.patterns.append(
                PatternRule(
                    name=p["name"],
                    description=p["description"],
                    severity=p["severity"],
                    conditions=conditions,
                    logic=p.get("logic", "AND"),
                    action=p.get("action", "alert"),
                )
            )

    def load_config(self, config_path: str) -> None:
        """Load patterns from a YAML or JSON config file."""
        path = Path(config_path)
        if not path.exists():
            log_event(logger, "pattern_config_not_found", level="warning", path=str(path))
            return

        try:
            with open(path) as f:
                if path.suffix in (".yaml", ".yml"):
                    data = yaml.safe_load(f)
                else:
                    data = json.load(f)

            for p in data.get("patterns", []):
                conditions = []
                for c in p.get("conditions", []):
                    conditions.append(
                        PatternCondition(
                            feature=c["feature"],
                            operator=c["operator"],
                            value=c["value"],
                            window=c.get("window"),
                        )
                    )
                self.patterns.append(
                    PatternRule(
                        name=p["name"],
                        description=p["description"],
                        severity=p["severity"],
                        conditions=conditions,
                        logic=p.get("logic", "AND"),
                        action=p.get("action", "alert"),
                        enabled=p.get("enabled", True),
                    )
                )

            log_event(
                logger,
                "pattern_config_loaded",
                level="info",
                path=str(path),
                patterns=len(data.get("patterns", [])),
            )

        except Exception as e:
            log_event(logger, "pattern_config_error", level="error", error=str(e))

    def match(self, dpi_result: DPIResult) -> List[PatternMatch]:
        """Match DPI features against all patterns.

        Returns:
            List of PatternMatch for matched patterns
        """
        matches = []
        features = dpi_result_to_dict(dpi_result)

        for pattern in self.patterns:
            if not pattern.enabled:
                continue

            result = self._evaluate_pattern(pattern, features)
            if result:
                matches.append(result)
                self._match_history.append(result)
                if len(self._match_history) > self._max_history:
                    self._match_history = self._match_history[-self._max_history :]

        return matches

    def _evaluate_pattern(self, pattern: PatternRule, features: Dict) -> Optional[PatternMatch]:
        """Evaluate a single pattern against features."""
        matched = []
        total = len(pattern.conditions)

        for condition in pattern.conditions:
            if self._evaluate_condition(condition, features):
                matched.append(f"{condition.feature} {condition.operator} {condition.value}")

        if not matched:
            return None

        # Check logic
        if pattern.logic == "AND" and len(matched) < total:
            return None
        elif pattern.logic == "OR" and len(matched) == 0:
            return None

        # Calculate confidence
        confidence = len(matched) / total if total > 0 else 0.0

        return PatternMatch(
            pattern_name=pattern.name,
            severity=pattern.severity,
            confidence=round(confidence, 2),
            matched_conditions=matched,
            action=pattern.action,
            details={
                "description": pattern.description,
                "total_conditions": total,
                "matched_conditions": len(matched),
            },
        )

    def _evaluate_condition(self, condition: PatternCondition, features: Dict) -> bool:
        """Evaluate a single condition."""
        feature_val = features.get(condition.feature)

        if feature_val is None:
            return False

        try:
            if condition.operator == "==":
                return feature_val == condition.value
            elif condition.operator == "!=":
                return feature_val != condition.value
            elif condition.operator == ">":
                return float(feature_val) > float(condition.value)
            elif condition.operator == "<":
                return float(feature_val) < float(condition.value)
            elif condition.operator == ">=":
                return float(feature_val) >= float(condition.value)
            elif condition.operator == "<=":
                return float(feature_val) <= float(condition.value)
            elif condition.operator == "contains":
                if isinstance(feature_val, list):
                    return condition.value in feature_val
                return str(condition.value) in str(feature_val)
            elif condition.operator == "not_in":
                return feature_val not in condition.value
            elif condition.operator == "in":
                return feature_val in condition.value
        except (ValueError, TypeError):
            return False

        return False

    def get_stats(self) -> Dict:
        """Get pattern engine statistics."""
        severity_counts = {}
        for m in self._match_history:
            severity_counts[m.severity] = severity_counts.get(m.severity, 0) + 1

        return {
            "total_patterns": len(self.patterns),
            "enabled_patterns": sum(1 for p in self.patterns if p.enabled),
            "total_matches": len(self._match_history),
            "matches_by_severity": severity_counts,
        }

    def get_recent_matches(self, limit: int = 50) -> List[Dict]:
        """Get recent pattern matches."""
        return [
            {
                "pattern": m.pattern_name,
                "severity": m.severity,
                "confidence": m.confidence,
                "action": m.action,
                "conditions": m.matched_conditions,
                "timestamp": m.timestamp,
            }
            for m in self._match_history[-limit:]
        ]
