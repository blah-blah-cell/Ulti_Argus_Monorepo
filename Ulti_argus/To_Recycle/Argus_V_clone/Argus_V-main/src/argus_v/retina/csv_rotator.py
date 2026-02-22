"""Rotating CSV writer with mythological naming scheme."""

from __future__ import annotations

import csv
import logging
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, TextIO

from .aggregator import WindowStats

logger = logging.getLogger(__name__)


# Mythological names for file rotation
MYTHOLOGICAL_NAMES = [
    # Greek
    "zeus", "hera", "poseidon", "hades", "athena", "apollo", "artemis", "aphrodite",
    "ares", "hephaestus", "hermes", "dionysus", "demeter", "hestia",
    # Norse  
    "odin", "thor", "loki", "freyja", "frigg", "tyr", "heimdall", "baldr",
    "hodr", "vidar", "vali", "halla", "sif", "heimdall",
    # Egyptian
    "ra", "osiris", "isis", "horus", "set", "anubis", "thoth", "bastet",
    "sekhmet", "hathor", "nephthys", "ptah", "sobek", "nut",
    # Celtic
    "morrigan", "lugh", "brigid", "danu", "dagon", "cernunnos", "herne", "owen",
    # Roman
    "jupiter", "mars", "venus", "mercury", "neptune", "pluto", "minerva", "juno",
    # Other mythologies
    "quetzalcoatl", "tezcatlipoca", "shiva", "vishnu", "brahma", "durga", "lakshmi",
    "amaterasu", "susanoo", "tsukuyomi", "izanagi", "izanami",
]


class FileRotationError(Exception):
    """Exception raised during file rotation."""
    pass


class MythologicalCSVRotator:
    """CSV writer with mythological naming and automatic rotation."""
    
    def __init__(
        self,
        output_dir: Path,
        file_prefix: str = "retina_packets",
        max_rows_per_file: int = 10000,
        file_rotation_count: int = 10,
        write_header: bool = True,
    ):
        self.output_dir = Path(output_dir)
        self.file_prefix = file_prefix
        self.max_rows_per_file = max_rows_per_file
        self.file_rotation_count = file_rotation_count
        self.write_header = write_header
        
        # Thread safety
        self._lock = threading.RLock()
        
        # File state
        self._current_file_path: Optional[Path] = None
        self._current_file_handle: Optional[TextIO] = None
        self._file_writer: Optional[csv.DictWriter] = None
        self._current_row_count = 0
        self._current_name_index = 0
        
        # Statistics
        self._stats = {
            "files_written": 0,
            "total_rows": 0,
            "rotations": 0,
            "errors": 0,
        }
        
        # Create output directory
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Set up column headers for CSV
        self._csv_columns = [
            "timestamp",
            "window_start",
            "window_end", 
            "duration_seconds",
            "packet_count",
            "byte_count",
            "unique_flows",
            "rate_pps",
            "rate_bps",
            "src_ip_anon",
            "dst_ip_anon",
            "protocol",
            "src_port",
            "dst_port",
            "src_flow_packets",
            "src_flow_bytes",
            "dst_flow_packets", 
            "dst_flow_bytes",
        ]
    
    def get_current_file_path(self) -> Optional[Path]:
        """Get the path of the currently open file."""
        return self._current_file_path
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current statistics."""
        with self._lock:
            return {
                **self._stats,
                "current_file": str(self._current_file_path) if self._current_file_path else None,
                "current_row_count": self._current_row_count,
                "rotation_name": self._get_mythological_name(self._current_name_index),
            }
    
    def write_window_stats(self, window_stats: WindowStats, flow_data: List[Dict[str, Any]]) -> None:
        """Write window statistics with per-flow breakdown to CSV."""
        with self._lock:
            try:
                # Ensure we have a file open
                if self._current_file_handle is None:
                    self._open_new_file()
                
                # Write each flow as a separate row for the window
                for flow in flow_data:
                    row = self._prepare_window_row(window_stats, flow)
                    self._write_row(row)
                
                self._stats["total_rows"] += len(flow_data)
                
            except Exception as e:
                self._stats["errors"] += 1
                logger.error(f"Error writing window stats: {e}")
                raise
    
    def flush(self) -> None:
        """Flush current file to disk."""
        with self._lock:
            if self._current_file_handle:
                self._current_file_handle.flush()
    
    def rotate_file(self) -> Optional[Path]:
        """Manually rotate to a new file."""
        with self._lock:
            old_file = self._current_file_path
            self._close_current_file()
            self._open_new_file()
            self._stats["rotations"] += 1
            
            logger.info(f"File rotation: {old_file} -> {self._current_file_path}")
            return old_file
    
    def _prepare_window_row(self, window_stats: WindowStats, flow_data: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare a single row for CSV output."""
        return {
            "timestamp": datetime.fromtimestamp(time.time(), tz=timezone.utc).isoformat(),
            "window_start": datetime.fromtimestamp(window_stats.start_time, tz=timezone.utc).isoformat(),
            "window_end": datetime.fromtimestamp(window_stats.end_time, tz=timezone.utc).isoformat(),
            "duration_seconds": window_stats.duration_seconds,
            "packet_count": window_stats.packet_count,
            "byte_count": window_stats.byte_count,
            "unique_flows": window_stats.unique_flows,
            "rate_pps": round(window_stats.rate_pps, 2),
            "rate_bps": round(window_stats.rate_bps, 2),
            "src_ip_anon": flow_data.get("src_ip", ""),
            "dst_ip_anon": flow_data.get("dst_ip", ""),
            "protocol": flow_data.get("protocol", ""),
            "src_port": flow_data.get("src_port", ""),
            "dst_port": flow_data.get("dst_port", ""),
            "src_flow_packets": flow_data.get("src_packets", 0),
            "src_flow_bytes": flow_data.get("src_bytes", 0),
            "dst_flow_packets": flow_data.get("dst_packets", 0),
            "dst_flow_bytes": flow_data.get("dst_bytes", 0),
        }
    
    def _write_row(self, row: Dict[str, Any]) -> None:
        """Write a single row to the current file."""
        if not self._file_writer or not self._current_file_handle:
            raise FileRotationError("No file handle available for writing")
        
        try:
            self._file_writer.writerow(row)
            self._current_row_count += 1
            
            # Check if we need to rotate
            if self._current_row_count >= self.max_rows_per_file:
                self.rotate_file()
                
        except Exception as e:
            self._stats["errors"] += 1
            logger.error(f"Error writing CSV row: {e}")
            raise FileRotationError(f"Failed to write row: {e}")
    
    def _open_new_file(self) -> None:
        """Open a new file with mythological naming."""
        # Generate new filename
        name = self._get_mythological_name(self._current_name_index)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.file_prefix}_{name}_{timestamp}.csv"
        
        self._current_file_path = self.output_dir / filename
        
        try:
            # Open file and create writer
            self._current_file_handle = open(
                self._current_file_path, 
                "w", 
                newline="", 
                encoding="utf-8"
            )
            self._file_writer = csv.DictWriter(
                self._current_file_handle, 
                fieldnames=self._csv_columns
            )
            
            # Write header if requested
            if self.write_header:
                self._file_writer.writeheader()
            
            self._current_row_count = 0
            self._current_name_index = (self._current_name_index + 1) % len(MYTHOLOGICAL_NAMES)
            self._stats["files_written"] += 1
            
            logger.info(f"Opened new CSV file: {self._current_file_path}")
            
        except Exception as e:
            self._stats["errors"] += 1
            logger.error(f"Failed to open new file {self._current_file_path}: {e}")
            raise FileRotationError(f"Failed to open file: {e}")
    
    def _close_current_file(self) -> None:
        """Close the current file."""
        if self._current_file_handle:
            try:
                self._current_file_handle.flush()
                self._current_file_handle.close()
                logger.debug(f"Closed file: {self._current_file_path}")
            except Exception as e:
                logger.error(f"Error closing file {self._current_file_path}: {e}")
            finally:
                self._current_file_handle = None
                self._file_writer = None
                self._current_file_path = None
                self._current_row_count = 0
    
    def _get_mythological_name(self, index: int) -> str:
        """Get mythological name for the given index."""
        return MYTHOLOGICAL_NAMES[index % len(MYTHOLOGICAL_NAMES)]
    
    def list_files(self) -> List[Path]:
        """List all CSV files in the output directory."""
        pattern = f"{self.file_prefix}_*.csv"
        return sorted(self.output_dir.glob(pattern))
    
    def cleanup_old_files(self, keep_count: Optional[int] = None) -> int:
        """Clean up old rotation files, keeping only the most recent ones."""
        if keep_count is None:
            keep_count = self.file_rotation_count
        
        files = self.list_files()
        if len(files) <= keep_count:
            return 0
        
        files_to_delete = files[:-keep_count]
        deleted_count = 0
        
        for file_path in files_to_delete:
            try:
                file_path.unlink()
                deleted_count += 1
                logger.info(f"Deleted old file: {file_path}")
            except Exception as e:
                logger.error(f"Failed to delete {file_path}: {e}")
        
        return deleted_count
    
    def get_file_info(self, file_path: Path) -> Dict[str, Any]:
        """Get information about a CSV file."""
        if not file_path.exists():
            return {"error": "File does not exist"}
        
        stat = file_path.stat()
        return {
            "path": str(file_path),
            "size_bytes": stat.st_size,
            "modified": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
            "name": file_path.name,
            "mythological_name": self._extract_mythological_name(file_path.name),
        }
    
    def _extract_mythological_name(self, filename: str) -> Optional[str]:
        """Extract the mythological name from a filename."""
        # Expected format: {prefix}_{name}_{timestamp}.csv
        parts = filename.replace(".csv", "").split("_")
        if len(parts) >= 3:
            potential_name = parts[1]
            return potential_name if potential_name in MYTHOLOGICAL_NAMES else None
        return None
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        with self._lock:
            self._close_current_file()
        return False


class FirebaseCSVStager:
    """Stages CSV files for upload to Firebase."""
    
    def __init__(self, rotator: MythologicalCSVRotator, staging_dir: Path):
        self.rotator = rotator
        self.staging_dir = Path(staging_dir)
        self.staging_dir.mkdir(parents=True, exist_ok=True)
    
    def stage_completed_files(self) -> List[Path]:
        """Stage completed files for Firebase upload."""
        staged_files = []
        
        # Get completed files from rotator
        rotator_files = self.rotator.list_files()
        
        for file_path in rotator_files:
            try:
                # Check if file is old enough to be considered complete
                stat = file_path.stat()
                file_age = time.time() - stat.st_mtime
                
                # Consider file complete if it's older than 60 seconds
                if file_age > 60:
                    staged_path = self.staging_dir / file_path.name
                    
                    # Move file to staging (atomic operation)
                    file_path.rename(staged_path)
                    staged_files.append(staged_path)
                    
                    logger.info(f"Staged file for Firebase upload: {staged_path}")
                    
            except Exception as e:
                logger.error(f"Failed to stage file {file_path}: {e}")
        
        return staged_files
    
    def get_staged_files(self) -> List[Path]:
        """Get list of files currently in staging."""
        pattern = self.staging_dir / "*.csv"
        return sorted(self.staging_dir.glob("*.csv"))
    
    def mark_uploaded(self, file_path: Path) -> bool:
        """Mark a file as uploaded by moving it to uploaded directory."""
        try:
            uploaded_dir = self.staging_dir / "uploaded"
            uploaded_dir.mkdir(exist_ok=True)
            
            uploaded_path = uploaded_dir / file_path.name
            file_path.rename(uploaded_path)
            
            logger.info(f"Marked file as uploaded: {uploaded_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to mark file as uploaded {file_path}: {e}")
            return False