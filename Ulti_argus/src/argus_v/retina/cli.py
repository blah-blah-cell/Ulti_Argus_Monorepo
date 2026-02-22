#!/usr/bin/env python3
"""Argus_V Retina CLI - Command line interface for packet capture and analysis."""

from __future__ import annotations

import argparse
import logging
import signal
import sys
import time
from pathlib import Path

from ..oracle_core.logging import configure_logging, log_event, JsonFormatter, PrivacyFilter
from .config import RetinaConfig
from .daemon import RetinaDaemon


def setup_argparser() -> argparse.ArgumentParser:
    """Set up command line argument parser."""
    parser = argparse.ArgumentParser(
        description="Argus_V Retina - Network packet collector and analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --config /etc/argus-v/retina.yaml daemon
  %(prog)s --config /etc/argus-v/retina.yaml --interface eth0 test
  %(prog)s --config /etc/argus-v/retina.yaml status
  %(prog)s --config /etc/argus-v/retina.yaml stats
        """
    )
    
    parser.add_argument(
        "--config", 
        type=str, 
        default="/etc/argus-v/retina.yaml",
        help="Path to configuration file (default: /etc/argus-v/retina.yaml)"
    )
    
    parser.add_argument(
        "--interface", 
        type=str,
        help="Network interface to monitor (overrides config)"
    )
    
    parser.add_argument(
        "--log-level", 
        type=str, 
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Set logging level (overrides config)"
    )
    
    parser.add_argument(
        "--log-file",
        type=str,
        help="Log to file instead of stdout"
    )
    
    parser.add_argument(
        "--daemon",
        action="store_true",
        help="Run as daemon (foreground with proper signal handling)"
    )
    
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Load configuration and verify setup without starting capture"
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # Daemon command
    daemon_parser = subparsers.add_parser("daemon", help="Run as daemon")
    daemon_parser.add_argument(
        "--pid-file",
        type=str,
        default="/var/run/argus-v-retina.pid",
        help="PID file for daemon (default: /var/run/argus-v-retina.pid)"
    )
    
    # Test command
    test_parser = subparsers.add_parser("test", help="Test configuration and interfaces")
    test_parser.add_argument(
        "--duration",
        type=int,
        default=10,
        help="Test duration in seconds (default: 10)"
    )
    
    # Status command
    status_parser = subparsers.add_parser("status", help="Show daemon status")
    
    # Stats command
    stats_parser = subparsers.add_parser("stats", help="Show capture statistics")
    
    # Validate command
    validate_parser = subparsers.add_parser("validate", help="Validate configuration file")
    
    # List interfaces command
    interfaces_parser = subparsers.add_parser("interfaces", help="List available network interfaces")
    
    return parser


def load_retina_config(config_path: str, overrides: dict = None) -> RetinaConfig:
    """Load and validate retina configuration."""
    config_path = Path(config_path)
    
    if not config_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
    
    try:
        # Load the YAML configuration file
        import yaml
        with open(config_path, 'r') as f:
            config_data = yaml.safe_load(f)
        
        # Create environment mapping for config processing
        env = dict(__import__("os").environ)
        
        # Load retina configuration
        retina_config = RetinaConfig.from_mapping(
            config_data,
            path="$",
            env=env
        )
        
        # Apply overrides if provided
        if overrides:
            if overrides.get("interface") is not None:
                # Update capture interface
                current_capture = retina_config.capture
                new_capture = current_capture.__class__(
                    interface=overrides["interface"],
                    snaplen=current_capture.snaplen,
                    promiscuous=current_capture.promiscuous,
                    timeout_ms=current_capture.timeout_ms,
                    buffer_size_mb=current_capture.buffer_size_mb,
                    use_scapy=current_capture.use_scapy,
                )
                
                retina_config = RetinaConfig(
                    capture=new_capture,
                    aggregation=retina_config.aggregation,
                    health=retina_config.health,
                    anonymization=retina_config.anonymization,
                    enabled=retina_config.enabled,
                )
        
        # Apply log level override if provided
        if overrides and "log_level" in overrides:
            # Log level is handled separately, not part of config
            pass
        
        return retina_config
        
    except Exception as e:
        raise ValueError(f"Failed to load retina configuration: {e}")


def configure_logging_from_args(args) -> logging.Logger:
    """Configure logging based on command line arguments."""
    log_level = getattr(args, "log_level", None)
    log_file = getattr(args, "log_file", None)
    
    # Configure base logging (sets up root logger with stream handler)
    logger = configure_logging(level=log_level)

    # Set up file logging if requested
    if log_file:
        try:
            # Ensure directory exists
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)

            # Create file handler
            file_handler = logging.FileHandler(str(log_path))
            file_handler.name = "argus_file"
            file_handler.setFormatter(JsonFormatter())
            file_handler.addFilter(PrivacyFilter())

            # Add to root logger to capture all logs
            logging.getLogger().addHandler(file_handler)

        except Exception as e:
            logger.error(f"Failed to setup file logging to {log_file}: {e}")
    
    return logger


def cmd_daemon(args, logger: logging.Logger) -> int:
    """Run the retina daemon."""
    try:
        # Load configuration
        config = load_retina_config(args.config, vars(args))
        
        if not config.enabled:
            logger.info("Retina is disabled in configuration")
            return 0
        
        if args.dry_run:
            logger.info("Dry run mode - verifying configuration only")
            logger.info(f"Interface: {config.capture.interface}")
            logger.info(f"Window: {config.aggregation.window_seconds}s")
            logger.info(f"Output: {config.aggregation.output_dir}")
            return 0
        
        # Create and start daemon
        daemon = RetinaDaemon(config)
        
        # Set up signal handlers
        def signal_handler(signum, frame):
            logger.info(f"Received signal {signum}, shutting down...")
            daemon.stop()
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        # Start daemon
        daemon.start()
        
        # Run daemon loop
        try:
            while daemon.is_running():
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Received keyboard interrupt")
        finally:
            daemon.stop()
        
        return 0
        
    except Exception as e:
        logger.error(f"Daemon error: {e}")
        return 1


def cmd_test(args, logger: logging.Logger) -> int:
    """Test configuration and capture capabilities."""
    try:
        # Load configuration
        config = load_retina_config(args.config, vars(args))
        
        logger.info("Testing Retina configuration...")
        logger.info(f"Interface: {config.capture.interface}")
        logger.info(f"Window: {config.aggregation.window_seconds}s")
        logger.info(f"Output: {config.aggregation.output_dir}")
        
        # Test interface availability
        from .collector import CaptureEngine
        
        engine = CaptureEngine(
            interface=config.capture.interface,
            use_scapy=config.capture.use_scapy
        )
        
        logger.info(f"Interface {config.capture.interface} available: {engine.is_interface_available()}")
        
        if engine.is_interface_available():
            logger.info(f"Interface IP: {engine.get_interface_ip()}")
            logger.info(f"Interface MAC: {engine.get_interface_mac()}")
        
        # Test capture for specified duration
        if not args.dry_run:
            logger.info(f"Starting test capture for {args.duration} seconds...")
            
            packets_received = 0
            
            def packet_callback(packet_info):
                nonlocal packets_received
                packets_received += 1
                if packets_received <= 5:  # Log first few packets
                    logger.info(f"Packet: {packet_info.src_ip} -> {packet_info.dst_ip} ({packet_info.protocol})")
            
            with engine.capture_context(
                packet_callback,
                snaplen=config.capture.snaplen,
                promiscuous=config.capture.promiscuous,
                timeout_ms=config.capture.timeout_ms,
            ):
                # Test capture for duration
                for i in range(args.duration):
                    time.sleep(1)
                    if i % 5 == 0:
                        logger.info(f"Test capture running... {i}/{args.duration}s ({packets_received} packets)")
            
            logger.info(f"Test capture completed: {packets_received} packets received")
        
        return 0
        
    except Exception as e:
        logger.error(f"Test error: {e}")
        return 1


def cmd_status(args, logger: logging.Logger) -> int:
    """Show daemon status."""
    logger.info("Status command not yet implemented")
    return 0


def cmd_stats(args, logger: logging.Logger) -> int:
    """Show capture statistics."""
    logger.info("Stats command not yet implemented")
    return 0


def cmd_validate(args, logger: logging.Logger) -> int:
    """Validate configuration file."""
    try:
        # Try to load the configuration
        load_retina_config(args.config)
        print(f"✓ Configuration file {args.config} is valid")
        return 0
        
    except Exception as e:
        print(f"✗ Configuration validation failed: {e}")
        return 1


def cmd_interfaces(args, logger: logging.Logger) -> int:
    """List available network interfaces."""
    try:
        from .collector import CaptureEngine
        
        if CaptureEngine.HAS_SCAPY if hasattr(CaptureEngine, 'HAS_SCAPY') else False:
            from scapy.all import get_if_list
            interfaces = get_if_list()
        else:
            # Fallback to system command
            import subprocess
            result = subprocess.run(["ip", "link", "show"], capture_output=True, text=True)
            interfaces = []
            for line in result.stdout.split('\n'):
                if ': ' in line and 'state ' in line:
                    name = line.split(':')[1].strip().split('@')[0]
                    if not name.startswith('lo'):  # Skip loopback
                        interfaces.append(name)
        
        print("Available network interfaces:")
        for iface in interfaces:
            print(f"  {iface}")
        
        return 0
        
    except Exception as e:
        logger.error(f"Failed to list interfaces: {e}")
        return 1


def main() -> int:
    """Main CLI entry point."""
    parser = setup_argparser()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    # Configure logging
    logger = configure_logging_from_args(args)
    
    # Log startup
    log_event(logger, "Retina CLI starting", level="INFO", command=args.command)
    
    try:
        if args.command == "daemon":
            return cmd_daemon(args, logger)
        elif args.command == "test":
            return cmd_test(args, logger)
        elif args.command == "status":
            return cmd_status(args, logger)
        elif args.command == "stats":
            return cmd_stats(args, logger)
        elif args.command == "validate":
            return cmd_validate(args, logger)
        elif args.command == "interfaces":
            return cmd_interfaces(args, logger)
        else:
            logger.error(f"Unknown command: {args.command}")
            return 1
            
    except KeyboardInterrupt:
        logger.info("Operation cancelled by user")
        return 0
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return 1
    finally:
        log_event(logger, "Retina CLI exiting", level="INFO")


if __name__ == "__main__":
    sys.exit(main())