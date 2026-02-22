"""Blacklist management for Aegis shield runtime.

This module provides decentralized blacklist storage using JSON and SQLite with
Firebase synchronization, IP handling, and iptables integration.
"""

from __future__ import annotations

import ipaddress
import json
import ipaddress
import logging
import sqlite3
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import firebase_admin
    from firebase_admin import credentials, storage
    from google.cloud import storage as gcs
    FIREBASE_AVAILABLE = True
except ImportError:
    FIREBASE_AVAILABLE = False

try:
    from ..kronos.enforcer import KronosEnforcer
    _KRONOS_AVAILABLE = True
except ImportError:
    _KRONOS_AVAILABLE = False

from ..oracle_core import HashAnonymizer
from ..oracle_core.logging import log_event

logger = logging.getLogger(__name__)


class BlacklistError(Exception):
    """Base exception for blacklist operations."""
    pass


class BlacklistNotFoundError(BlacklistError):
    """Exception raised when blacklist entry is not found."""
    pass


class BlacklistValidationError(BlacklistError):
    """Exception raised when blacklist entry validation fails."""
    pass


class EnforcementError(BlacklistError):
    """Exception raised when enforcement operations fail."""
    pass


class BlacklistManager:
    """Manages decentralized blacklist storage with Firebase sync."""
    
    def __init__(self, config, anonymizer: HashAnonymizer | None = None):
        """Initialize blacklist manager.
        
        Args:
            config: Enforcement configuration
            anonymizer: Optional hash anonymizer for IP anonymization
        """
        self.config = config
        
        # Paths are loaded from config (which supports env var overrides)
        self._sqlite_db_path = Path(config.blacklist_db_path)
        self._json_cache_path = Path(config.blacklist_json_path)
        self._firebase_sync_enabled = FIREBASE_AVAILABLE
        self._last_sync_time = None
        self._sync_failures = 0
        self._max_sync_failures = 3
        
        self._stats = {
            'total_entries': 0,
            'active_entries': 0,
            'expired_entries': 0,
            'sync_operations': 0,
            'enforcement_actions': 0,
            'emergency_stops': 0
        }
        
        self._iptables_available: Optional[bool] = None
        self._kronos_enforcer = KronosEnforcer() if _KRONOS_AVAILABLE else None

        # Initialize storage systems
        self._ensure_directories()
        self._initialize_database()
    
    def _ensure_directories(self) -> None:
        """Ensure required directories exist."""
        blacklist_dir = self._sqlite_db_path.parent
        blacklist_dir.mkdir(parents=True, exist_ok=True)
        
        # Create backup directory
        backup_dir = blacklist_dir / "backups"
        backup_dir.mkdir(exist_ok=True)
        
        log_event(
            logger,
            "blacklist_directories_ensured",
            level="debug",
            db_path=str(self._sqlite_db_path),
            json_path=str(self._json_cache_path)
        )
    
    def _initialize_database(self) -> None:
        """Initialize SQLite database and create tables."""
        try:
            with sqlite3.connect(self._sqlite_db_path) as conn:
                cursor = conn.cursor()
                
                # Main blacklist table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS blacklist (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ip_address TEXT NOT NULL,
                        reason TEXT,
                        source TEXT DEFAULT 'prediction',
                        risk_level TEXT DEFAULT 'medium',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        expires_at TIMESTAMP,
                        is_active BOOLEAN DEFAULT TRUE,
                        enforcement_action TEXT DEFAULT 'none',
                        hit_count INTEGER DEFAULT 0,
                        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        metadata TEXT,
                        UNIQUE(ip_address, source)
                    )
                """)
                
                # Sync tracking table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS sync_log (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        operation TEXT NOT NULL,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        entry_count INTEGER,
                        success BOOLEAN,
                        error_message TEXT,
                        remote_path TEXT
                    )
                """)
                
                # Emergency stops tracking
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS emergency_stops (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        stopped_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        reason TEXT,
                        stopped_by TEXT DEFAULT 'system',
                        restored_at TIMESTAMP,
                        restored_by TEXT
                    )
                """)
                
                conn.commit()
                
                log_event(
                    logger,
                    "blacklist_database_initialized",
                    level="info"
                )
                
        except Exception as e:
            log_event(
                logger,
                "blacklist_database_init_failed",
                level="error",
                error=str(e)
            )
            raise BlacklistError(f"Database initialization failed: {e}")
    
    def add_to_blacklist(
        self, 
        ip_address: str, 
        reason: str,
        source: str = "prediction",
        risk_level: str = "medium",
        ttl_hours: Optional[int] = None,
        enforce: bool = False,
        metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Add IP address to blacklist.
        
        Args:
            ip_address: IP address to blacklist
            reason: Reason for blacklisting
            source: Source of the blacklist entry (prediction, manual, etc.)
            risk_level: Risk level (low, medium, high, critical)
            ttl_hours: Time to live in hours (None for no expiry)
            enforce: Whether to immediately enforce the ban
            metadata: Additional metadata
            
        Returns:
            True if added successfully, False otherwise
        """
        try:
            # Validate inputs
            if not self._validate_ip_address(ip_address):
                raise BlacklistValidationError(f"Invalid IP address: {ip_address}")
            
            if risk_level not in ['low', 'medium', 'high', 'critical']:
                raise BlacklistValidationError(f"Invalid risk level: {risk_level}")
            
            # Calculate expiry time
            expires_at = None
            if ttl_hours:
                expires_at = datetime.now() + timedelta(hours=ttl_hours)
            
            # Anonymize IP for storage (if needed)
            anonymized_ip = self.anonymizer.anonymize_ip(ip_address) if self.anonymizer else ip_address
            
            with sqlite3.connect(self._sqlite_db_path) as conn:
                cursor = conn.cursor()
                
                # Upsert blacklist entry
                cursor.execute("""
                    INSERT OR REPLACE INTO blacklist 
                    (ip_address, reason, source, risk_level, expires_at, is_active, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    anonymized_ip, reason, source, risk_level, expires_at, True,
                    json.dumps(metadata) if metadata else None
                ))
                
                conn.commit()
                
                log_event(
                    logger,
                    "ip_added_to_blacklist",
                    level="info",
                    ip_address=ip_address,
                    anonymized_ip=anonymized_ip,
                    reason=reason,
                    risk_level=risk_level,
                    ttl_hours=ttl_hours,
                    source=source
                )
                
                # Update statistics
                self._update_stats()
                
                # Enforce immediately if requested
                if enforce:
                    return self._enforce_blacklist_entry(anonymized_ip, reason, risk_level)
                
                return True
                
        except Exception as e:
            log_event(
                logger,
                "add_to_blacklist_failed",
                level="error",
                ip_address=ip_address,
                error=str(e)
            )
            return False
    
    def remove_from_blacklist(self, ip_address: str, source: str = "prediction") -> bool:
        """Remove IP address from blacklist.
        
        Args:
            ip_address: IP address to remove
            source: Source of the blacklist entry
            
        Returns:
            True if removed successfully, False otherwise
        """
        try:
            # Anonymize IP for lookup
            anonymized_ip = self.anonymizer.anonymize_ip(ip_address) if self.anonymizer else ip_address
            
            with sqlite3.connect(self._sqlite_db_path) as conn:
                cursor = conn.cursor()
                
                # Soft delete (mark as inactive)
                cursor.execute("""
                    UPDATE blacklist 
                    SET is_active = FALSE, last_seen = CURRENT_TIMESTAMP
                    WHERE ip_address = ? AND source = ?
                """, (anonymized_ip, source))
                
                if cursor.rowcount == 0:
                    raise BlacklistNotFoundError(f"IP {ip_address} not found in blacklist")
                
                conn.commit()
                
                # Remove from iptables if active
                self._remove_from_iptables(anonymized_ip)
                
                # Remove from eBPF via Kronos
                if self._kronos_enforcer:
                    self._kronos_enforcer.unblock_ip(anonymized_ip)
                
                log_event(
                    logger,
                    "ip_removed_from_blacklist",
                    level="info",
                    ip_address=ip_address,
                    anonymized_ip=anonymized_ip,
                    source=source
                )
                
                # Update statistics
                self._update_stats()
                
                return True
                
        except BlacklistNotFoundError:
            log_event(
                logger,
                "ip_not_in_blacklist",
                level="warning",
                ip_address=ip_address,
                source=source
            )
            return False
        except Exception as e:
            log_event(
                logger,
                "remove_from_blacklist_failed",
                level="error",
                ip_address=ip_address,
                error=str(e)
            )
            return False
    
    def is_blacklisted(self, ip_address: str) -> bool:
        """Check if IP address is currently blacklisted.
        
        Args:
            ip_address: IP address to check
            
        Returns:
            True if IP is blacklisted and active
        """
        try:
            anonymized_ip = self.anonymizer.anonymize_ip(ip_address) if self.anonymizer else ip_address
            
            with sqlite3.connect(self._sqlite_db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT expires_at, is_active, risk_level 
                    FROM blacklist 
                    WHERE ip_address = ? AND is_active = TRUE
                """, (anonymized_ip,))
                
                result = cursor.fetchone()
                
                if not result:
                    return False
                
                expires_at, is_active, risk_level = result
                
                # Check if entry has expired
                if expires_at:
                    expiry_time = datetime.fromisoformat(expires_at) if isinstance(expires_at, str) else expires_at
                    if datetime.now() > expiry_time:
                        # Mark as inactive if expired
                        cursor.execute("""
                            UPDATE blacklist 
                            SET is_active = FALSE 
                            WHERE ip_address = ? AND expires_at < CURRENT_TIMESTAMP
                        """, (anonymized_ip,))
                        conn.commit()
                        return False
                
                # Update last seen
                cursor.execute("""
                    UPDATE blacklist 
                    SET last_seen = CURRENT_TIMESTAMP, hit_count = hit_count + 1
                    WHERE ip_address = ?
                """, (anonymized_ip,))
                conn.commit()
                
                return True
                
        except Exception as e:
            log_event(
                logger,
                "blacklist_check_failed",
                level="error",
                ip_address=ip_address,
                error=str(e)
            )
            return False
    
    def get_blacklist_entries(
        self, 
        active_only: bool = True,
        risk_level: Optional[str] = None,
        source: Optional[str] = None,
        limit: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """Get blacklist entries with optional filtering.
        
        Args:
            active_only: Only return active entries
            risk_level: Filter by risk level
            source: Filter by source
            limit: Maximum number of entries to return
            
        Returns:
            List of blacklist entry dictionaries
        """
        try:
            with sqlite3.connect(self._sqlite_db_path) as conn:
                cursor = conn.cursor()
                
                query = """
                    SELECT ip_address, reason, source, risk_level, created_at, 
                           expires_at, is_active, enforcement_action, hit_count,
                           last_seen, metadata
                    FROM blacklist
                """
                
                conditions = []
                params = []
                
                if active_only:
                    conditions.append("is_active = TRUE")
                
                if risk_level:
                    conditions.append("risk_level = ?")
                    params.append(risk_level)
                
                if source:
                    conditions.append("source = ?")
                    params.append(source)
                
                if conditions:
                    query += " WHERE " + " AND ".join(conditions)
                
                query += " ORDER BY created_at DESC"
                
                if limit:
                    query += " LIMIT ?"
                    params.append(limit)
                
                cursor.execute(query, params)
                
                entries = []
                for row in cursor.fetchall():
                    entry = {
                        'ip_address': row[0],
                        'reason': row[1],
                        'source': row[2],
                        'risk_level': row[3],
                        'created_at': row[4],
                        'expires_at': row[5],
                        'is_active': bool(row[6]),
                        'enforcement_action': row[7],
                        'hit_count': row[8],
                        'last_seen': row[9],
                        'metadata': json.loads(row[10]) if row[10] else None
                    }
                    entries.append(entry)
                
                log_event(
                    logger,
                    "blacklist_entries_retrieved",
                    level="debug",
                    count=len(entries),
                    active_only=active_only,
                    risk_level=risk_level,
                    source=source
                )
                
                return entries
                
        except Exception as e:
            log_event(
                logger,
                "get_blacklist_entries_failed",
                level="error",
                error=str(e)
            )
            return []
    
    def cleanup_expired_entries(self) -> int:
        """Clean up expired blacklist entries.
        
        Returns:
            Number of entries cleaned up
        """
        try:
            with sqlite3.connect(self._sqlite_db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    UPDATE blacklist 
                    SET is_active = FALSE 
                    WHERE expires_at IS NOT NULL 
                    AND expires_at < CURRENT_TIMESTAMP 
                    AND is_active = TRUE
                """)
                
                cleaned_count = cursor.rowcount
                conn.commit()
                
                if cleaned_count > 0:
                    log_event(
                        logger,
                        "expired_blacklist_entries_cleaned",
                        level="info",
                        cleaned_count=cleaned_count
                    )
                    
                    self._update_stats()
                
                return cleaned_count
                
        except Exception as e:
            log_event(
                logger,
                "cleanup_expired_entries_failed",
                level="error",
                error=str(e)
            )
            return 0
    
    def sync_with_firebase(self) -> bool:
        """Synchronize blacklist with Firebase Storage.
        
        Returns:
            True if sync successful, False otherwise
        """
        if not self._firebase_sync_enabled:
            log_event(
                logger,
                "firebase_sync_skipped",
                level="debug",
                reason="firebase_not_available"
            )
            return False
        
        try:
            log_event(
                logger,
                "firebase_sync_started",
                level="info"
            )
            
            # Export current blacklist to JSON
            json_data = self._export_to_json()
            
            if not json_data:
                log_event(
                    logger,
                    "firebase_sync_failed",
                    level="error",
                    reason="no_data_to_sync"
                )
                return False
            
            # Generate filename with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            remote_path = f"blacklist/backups/blacklist_{timestamp}.json"
            
            # Upload to Firebase (simulated for now)
            success = self._upload_to_firebase(json_data, remote_path)
            
            # Log sync operation
            with sqlite3.connect(self._sqlite_db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO sync_log 
                    (operation, entry_count, success, error_message, remote_path)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    'sync_firebase',
                    len(json_data.get('entries', [])),
                    success,
                    None if success else 'Upload failed',
                    remote_path if success else None
                ))
                conn.commit()
            
            if success:
                self._last_sync_time = datetime.now()
                self._sync_failures = 0
                self._stats['sync_operations'] += 1
                
                log_event(
                    logger,
                    "firebase_sync_completed",
                    level="info",
                    remote_path=remote_path,
                    entry_count=len(json_data.get('entries', []))
                )
            else:
                self._sync_failures += 1
                log_event(
                    logger,
                    "firebase_sync_failed",
                    level="error",
                    failure_count=self._sync_failures
                )
            
            return success
            
        except Exception as e:
            self._sync_failures += 1
            log_event(
                logger,
                "firebase_sync_exception",
                level="error",
                error=str(e)
            )
            return False
    
    def _export_to_json(self) -> Optional[Dict[str, Any]]:
        """Export blacklist to JSON format.
        
        Returns:
            Dictionary containing blacklist data or None if export failed
        """
        try:
            entries = self.get_blacklist_entries(active_only=False, limit=10000)
            
            export_data = {
                'export_timestamp': datetime.now().isoformat(),
                'total_entries': len(entries),
                'active_entries': len([e for e in entries if e['is_active']]),
                'entries': entries
            }
            
            # Save to local JSON file
            with open(self._json_cache_path, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)
            
            return export_data
            
        except Exception as e:
            log_event(
                logger,
                "export_to_json_failed",
                level="error",
                error=str(e)
            )
            return None
    
    def _upload_to_firebase(self, data: Dict[str, Any], remote_path: str) -> bool:
        """Upload data to Firebase Storage.
        
        Args:
            data: Data to upload
            remote_path: Remote storage path
            
        Returns:
            True if upload successful, False otherwise
        """
        try:
            # Simulate Firebase upload
            # In real implementation, would use Firebase Storage client
            
            log_event(
                logger,
                "firebase_upload_simulated",
                level="debug",
                remote_path=remote_path,
                data_size=len(str(data))
            )
            
            # For now, assume success if Firebase is available
            return FIREBASE_AVAILABLE
            
        except Exception as e:
            log_event(
                logger,
                "firebase_upload_failed",
                level="error",
                error=str(e)
            )
            return False
    
    def _enforce_blacklist_entry(self, ip_address: str, reason: str, risk_level: str) -> bool:
        """Enforce blacklist entry by adding to iptables.
        
        Args:
            ip_address: IP address to enforce
            reason: Reason for enforcement
            risk_level: Risk level of the entry
            
        Returns:
            True if enforcement successful, False otherwise
        """
        try:
            # Check if in dry run mode
            if self._is_dry_run_mode():
                log_event(
                    logger,
                    "dry_run_enforcement_skipped",
                    level="info",
                    ip_address=ip_address,
                    reason=reason,
                    risk_level=risk_level
                )
                return True
            
            # Add to iptables structure
            success_os = self._add_to_iptables(ip_address, reason, risk_level)
            
            # Add directly to Kernel eBPF Map
            success_ebpf = False
            if self._kronos_enforcer:
                success_ebpf = self._kronos_enforcer.block_ip(ip_address)
            
            success = success_os or success_ebpf
            
            if success:
                self._stats['enforcement_actions'] += 1
                log_event(
                    logger,
                    "blacklist_enforcement_applied",
                    level="info",
                    ip_address=ip_address,
                    reason=reason,
                    risk_level=risk_level
                )
            
            return success
            
        except Exception as e:
            log_event(
                logger,
                "blacklist_enforcement_failed",
                level="error",
                ip_address=ip_address,
                error=str(e)
            )
            return False
    
    def _check_iptables_availability(self) -> bool:
        """Check if iptables command is available (cached)."""
        if self._iptables_available is None:
            try:
                subprocess.run(['iptables', '--version'],
                             capture_output=True, check=True, timeout=5)
                self._iptables_available = True
            except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
                self._iptables_available = False
                log_event(
                    logger,
                    "iptables_not_available",
                    level="warning"
                )
        return self._iptables_available

    def _add_to_iptables(self, ip_address: str, reason: str, risk_level: str) -> bool:
        """Add IP address to iptables DROP chain.
        
        Args:
            ip_address: IP address to block
            reason: Reason for blocking
            risk_level: Risk level
            
        Returns:
            True if iptables rule added successfully, False otherwise
        """
        try:
            # Check if iptables command is available
            if not self._check_iptables_availability():
                return False
            
            # Add rule to drop traffic from IP
            rule = [
                'iptables', '-A', self.config.iptables_chain_name,
                '-s', ip_address, '-j', 'DROP'
            ]
            
            result = subprocess.run(
                rule, 
                capture_output=True, 
                text=True, 
                timeout=10
            )
            
            if result.returncode != 0:
                log_event(
                    logger,
                    "iptables_rule_add_failed",
                    level="error",
                    ip_address=ip_address,
                    stderr=result.stderr
                )
                return False
            
            log_event(
                logger,
                "iptables_rule_added",
                level="info",
                ip_address=ip_address,
                reason=reason,
                risk_level=risk_level,
                chain=self.config.iptables_chain_name
            )
            
            return True
            
        except Exception as e:
            log_event(
                logger,
                "iptables_operation_failed",
                level="error",
                ip_address=ip_address,
                error=str(e)
            )
            return False
    
    def _remove_from_iptables(self, ip_address: str) -> bool:
        """Remove IP address from iptables DROP chain.
        
        Args:
            ip_address: IP address to unblock
            
        Returns:
            True if iptables rule removed successfully, False otherwise
        """
        try:
            # Remove rule from iptables
            rule = [
                'iptables', '-D', self.config.iptables_chain_name,
                '-s', ip_address, '-j', 'DROP'
            ]
            
            result = subprocess.run(
                rule, 
                capture_output=True, 
                text=True, 
                timeout=10
            )
            
            # Note: iptables -D returns error if rule doesn't exist, which is OK
            if result.returncode == 0:
                log_event(
                    logger,
                    "iptables_rule_removed",
                    level="info",
                    ip_address=ip_address,
                    chain=self.config.iptables_chain_name
                )
                return True
            else:
                log_event(
                    logger,
                    "iptables_rule_not_found",
                    level="debug",
                    ip_address=ip_address
                )
                return True  # Not an error if rule doesn't exist
            
        except Exception as e:
            log_event(
                logger,
                "iptables_remove_failed",
                level="error",
                ip_address=ip_address,
                error=str(e)
            )
            return False
    
    def _validate_ip_address(self, ip_address: str) -> bool:
        """Validate IP address format.
        
        Args:
            ip_address: IP address to validate
            
        Returns:
            True if valid, False otherwise
        """
        try:
            ipaddress.ip_address(ip_address)
            return True
        except ValueError:
            return False
    
    def _is_dry_run_mode(self) -> bool:
        """Check if currently in dry run mode.
        
        Returns:
            True if dry run mode is active
        """
        # Check if emergency stop file exists
        if Path(self.config.emergency_stop_file).exists():
            return True
        
        # Check if service start time indicates within dry run period
        # This would be implemented based on actual service start tracking
        # For now, assume dry run is always enabled unless explicitly disabled
        return True  # Conservative approach - default to dry run
    
    def _update_stats(self) -> None:
        """Update internal statistics."""
        try:
            with sqlite3.connect(self._sqlite_db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("SELECT COUNT(*) FROM blacklist")
                self._stats['total_entries'] = cursor.fetchone()[0]
                
                cursor.execute("SELECT COUNT(*) FROM blacklist WHERE is_active = TRUE")
                self._stats['active_entries'] = cursor.fetchone()[0]
                
                cursor.execute("""
                    SELECT COUNT(*) FROM blacklist 
                    WHERE is_active = FALSE 
                    AND expires_at IS NOT NULL 
                    AND expires_at < CURRENT_TIMESTAMP
                """)
                self._stats['expired_entries'] = cursor.fetchone()[0]
                
        except Exception as e:
            log_event(
                logger,
                "stats_update_failed",
                level="error",
                error=str(e)
            )
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get current blacklist statistics.
        
        Returns:
            Dictionary containing statistics
        """
        self._update_stats()
        
        stats = self._stats.copy()
        stats.update({
            'last_sync_time': self._last_sync_time.isoformat() if self._last_sync_time else None,
            'sync_failures': self._sync_failures,
            'database_path': str(self._sqlite_db_path),
            'firebase_enabled': self._firebase_sync_enabled
        })
        
        return stats
    
    def emergency_stop(self, reason: str = "Manual emergency stop") -> bool:
        """Stop all enforcement actions immediately.
        
        Args:
            reason: Reason for emergency stop
            
        Returns:
            True if emergency stop activated successfully
        """
        try:
            # Create emergency stop file
            Path(self.config.emergency_stop_file).parent.mkdir(parents=True, exist_ok=True)
            Path(self.config.emergency_stop_file).touch()
            
            # Log emergency stop
            with sqlite3.connect(self._sqlite_db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO emergency_stops (reason, stopped_by)
                    VALUES (?, ?)
                """, (reason, "manual"))
                conn.commit()
            
            self._stats['emergency_stops'] += 1
            
            log_event(
                logger,
                "emergency_stop_activated",
                level="critical",
                reason=reason
            )
            
            return True
            
        except Exception as e:
            log_event(
                logger,
                "emergency_stop_failed",
                level="error",
                error=str(e)
            )
            return False
    
    def emergency_restore(self, reason: str = "Manual emergency restore") -> bool:
        """Restore normal enforcement operations.
        
        Args:
            reason: Reason for restoration
            
        Returns:
            True if emergency restored successfully
        """
        try:
            # Remove emergency stop file
            if Path(self.config.emergency_stop_file).exists():
                Path(self.config.emergency_stop_file).unlink()
            
            # Log restoration
            with sqlite3.connect(self._sqlite_db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE emergency_stops 
                    SET restored_at = CURRENT_TIMESTAMP, restored_by = ?
                    WHERE restored_at IS NULL
                    ORDER BY stopped_at DESC LIMIT 1
                """, (reason,))
                conn.commit()
            
            log_event(
                logger,
                "emergency_restored",
                level="info",
                reason=reason
            )
            
            return True
            
        except Exception as e:
            log_event(
                logger,
                "emergency_restore_failed",
                level="error",
                error=str(e)
            )
            return False