"""Unit tests for CSV rotation with mythological naming."""

from __future__ import annotations

import csv
import tempfile
from pathlib import Path

from argus_v.retina.aggregator import WindowStats
from argus_v.retina.csv_rotator import (
    FirebaseCSVStager,
    MythologicalCSVRotator,
)


class TestMythologicalCSVRotator:
    """Test MythologicalCSVRotator functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.temp_dir = Path(tempfile.mkdtemp())
        self.rotator = MythologicalCSVRotator(
            output_dir=self.temp_dir,
            file_prefix="test_packets",
            max_rows_per_file=5,
            file_rotation_count=3,
        )
    
    def teardown_method(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir)
    
    def test_rotator_initialization(self):
        """Test rotator initialization."""
        assert self.rotator.output_dir == self.temp_dir
        assert self.rotator.file_prefix == "test_packets"
        assert self.rotator.max_rows_per_file == 5
        assert self.rotator.file_rotation_count == 3
    
    def test_mythological_name_generation(self):
        """Test mythological name generation."""
        # Test that we can get different names
        names = [self.rotator._get_mythological_name(i) for i in range(10)]
        assert len(set(names)) > 1  # Should have variety
        assert all(name.islower() for name in names)
    
    def test_write_window_stats(self):
        """Test writing window statistics."""
        # Create test window stats
        window_stats = WindowStats(
            start_time=1234567890.0,
            end_time=1234567895.0,
            duration_seconds=5.0,
            packet_count=10,
            byte_count=1500,
            unique_flows=2,
            protocols={"TCP": 8, "UDP": 2},
            rate_pps=2.0,
            rate_bps=2400.0,
        )
        
        # Create test flow data
        flow_data = [
            {
                "src_ip": "ip_hash_001",
                "dst_ip": "ip_hash_002",
                "protocol": "TCP",
                "src_port": 443,
                "dst_port": 12345,
                "src_packets": 5,
                "src_bytes": 750,
                "dst_packets": 3,
                "dst_bytes": 450,
            },
            {
                "src_ip": "ip_hash_003",
                "dst_ip": "ip_hash_004",
                "protocol": "UDP",
                "src_port": 53,
                "dst_port": 5353,
                "src_packets": 1,
                "src_bytes": 150,
                "dst_packets": 1,
                "dst_bytes": 150,
            }
        ]
        
        # Write window stats
        self.rotator.write_window_stats(window_stats, flow_data)
        
        # Check that file was created
        files = self.rotator.list_files()
        assert len(files) == 1
        
        # Verify CSV content
        with open(files[0], 'r', newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            
            assert len(rows) == 2  # Two flow rows
            assert rows[0]['packet_count'] == '10'  # Window stats repeated
            assert rows[0]['src_ip_anon'] == 'ip_hash_001'
            assert rows[0]['protocol'] == 'TCP'
            assert rows[1]['src_ip_anon'] == 'ip_hash_003'
            assert rows[1]['protocol'] == 'UDP'
    
    def test_file_rotation(self):
        """Test file rotation based on row count."""
        window_stats = WindowStats(
            start_time=1234567890.0,
            end_time=1234567895.0,
            duration_seconds=5.0,
            packet_count=1,
            byte_count=64,
            unique_flows=1,
            protocols={"TCP": 1},
            rate_pps=0.2,
            rate_bps=102.4,
        )
        
        flow_data = [{
            "src_ip": "ip_hash",
            "dst_ip": "ip_hash",
            "protocol": "TCP",
            "src_port": 80,
            "dst_port": 12345,
            "src_packets": 1,
            "src_bytes": 64,
            "dst_packets": 0,
            "dst_bytes": 0,
        }]
        
        # Write enough data to trigger rotation (5 rows max)
        for i in range(6):  # One more than max_rows_per_file
            self.rotator.write_window_stats(window_stats, flow_data)
        
        # Should have 2 files now
        files = self.rotator.list_files()
        assert len(files) == 2
    
    def test_cleanup_old_files(self):
        """Test cleanup of old files."""
        # Create several files
        for i in range(5):
            self.rotator._open_new_file()
            self.rotator._current_row_count = i
        
        # Should have 5 files
        assert len(self.rotator.list_files()) == 5
        
        # Clean up, keeping only 3
        deleted_count = self.rotator.cleanup_old_files(keep_count=3)
        assert deleted_count == 2
        
        # Should have 3 files remaining
        assert len(self.rotator.list_files()) == 3
    
    def test_get_stats(self):
        """Test getting rotator statistics."""
        stats = self.rotator.get_stats()
        
        assert "files_written" in stats
        assert "total_rows" in stats
        assert "rotations" in stats
        assert "errors" in stats
        assert "current_file" in stats
        assert "rotation_name" in stats
    
    def test_extract_mythological_name(self):
        """Test extracting mythological name from filename."""
        filename = "test_packets_zeus_20231215_120000.csv"
        name = self.rotator._extract_mythological_name(filename)
        assert name == "zeus"
        
        # Test with non-mythological name
        filename = "test_packets_invalid_20231215_120000.csv"
        name = self.rotator._extract_mythological_name(filename)
        assert name is None
    
    def test_context_manager(self):
        """Test context manager functionality."""
        with self.rotator as rotator:
            assert rotator is self.rotator
        
        # Should have closed the file
        assert self.rotator._current_file_handle is None


class TestFirebaseCSVStager:
    """Test FirebaseCSVStager functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.temp_dir = Path(tempfile.mkdtemp())
        self.staging_dir = self.temp_dir / "staging"
        
        # Create rotator
        self.rotator = MythologicalCSVRotator(
            output_dir=self.temp_dir,
            file_prefix="test_packets",
        )
        
        # Create stager
        self.stager = FirebaseCSVStager(self.rotator, self.staging_dir)
    
    def teardown_method(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir)
    
    def test_stager_initialization(self):
        """Test stager initialization."""
        assert self.stager.rotator is self.rotator
        assert self.stager.staging_dir == self.staging_dir
        assert self.staging_dir.exists()
    
    def test_stage_completed_files(self):
        """Test staging completed files."""
        # Create a file in rotator output directory
        test_file = self.temp_dir / "test_packets_zeus_20231215_120000.csv"
        test_file.write_text("test,data\n1,2\n")
        
        # Set file modification time to be old (staged)
        import time
        old_time = time.time() - 120  # 2 minutes ago
        test_file.utime((old_time, old_time))
        
        # Stage files
        staged_files = self.stager.stage_completed_files()
        
        assert len(staged_files) == 1
        assert staged_files[0] == self.staging_dir / "test_packets_zeus_20231215_120000.csv"
        
        # Original file should be moved
        assert not test_file.exists()
        
        # Staged file should exist
        assert staged_files[0].exists()
    
    def test_get_staged_files(self):
        """Test getting staged files."""
        # Initially no files
        assert len(self.stager.get_staged_files()) == 0
        
        # Create a staged file
        staged_file = self.staging_dir / "staged_file.csv"
        staged_file.write_text("test,data\n1,2\n")
        
        staged_files = self.stager.get_staged_files()
        assert len(staged_files) == 1
        assert staged_files[0] == staged_file
    
    def test_mark_uploaded(self):
        """Test marking file as uploaded."""
        # Create a staged file
        staged_file = self.staging_dir / "test_file.csv"
        staged_file.write_text("test,data\n1,2\n")
        
        # Mark as uploaded
        result = self.stager.mark_uploaded(staged_file)
        assert result is True
        
        # Check file moved to uploaded directory
        uploaded_file = self.staging_dir / "uploaded" / "test_file.csv"
        assert uploaded_file.exists()
        assert not staged_file.exists()
    
    def test_stage_recent_files(self):
        """Test that recent files are not staged."""
        # Create a file with recent modification time
        test_file = self.temp_dir / "test_packets_recent_20231215_120000.csv"
        test_file.write_text("test,data\n1,2\n")
        
        # Set recent modification time (30 seconds ago)
        import time
        recent_time = time.time() - 30
        test_file.utime((recent_time, recent_time))
        
        # Stage files
        staged_files = self.stager.stage_completed_files()
        
        # Should not stage recent file
        assert len(staged_files) == 0
        assert test_file.exists()  # Original file still there


class TestMythologicalNames:
    """Test mythological names list."""
    
    def test_name_variety(self):
        """Test that we have a good variety of mythological names."""
        from argus_v.retina.csv_rotator import MYTHOLOGICAL_NAMES
        
        assert len(MYTHOLOGICAL_NAMES) > 20  # Should have decent variety
        
        # Check for names from different mythologies
        greek_names = ['zeus', 'hera', 'athena', 'apollo']
        norse_names = ['odin', 'thor', 'loki']
        egyptian_names = ['ra', 'osiris', 'isis']
        
        assert any(name in MYTHOLOGICAL_NAMES for name in greek_names)
        assert any(name in MYTHOLOGICAL_NAMES for name in norse_names)
        assert any(name in MYTHOLOGICAL_NAMES for name in egyptian_names)
        
        # All names should be lowercase
        assert all(name.islower() for name in MYTHOLOGICAL_NAMES)
        
        # No duplicates
        assert len(MYTHOLOGICAL_NAMES) == len(set(MYTHOLOGICAL_NAMES))