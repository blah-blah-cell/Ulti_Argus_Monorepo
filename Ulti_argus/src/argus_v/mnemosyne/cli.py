"""Command-line interface for the Mnemosyne trainer pipeline.

This module provides CLI commands for running the mnemosyne training pipeline,
validating setup, checking status, and managing artifacts.
"""

from __future__ import annotations

import argparse
import sys
from typing import Optional

from ..oracle_core.logging import configure_logging
from .config import load_mnemosyne_config
from .pipeline import MnemosynePipeline


def setup_logging(args) -> None:
    """Set up logging based on command line arguments."""
    log_level = getattr(args, 'log_level', 'INFO')
    configure_logging(level=log_level)


def cmd_train(args) -> int:
    """Run the mnemosyne training pipeline."""
    try:
        setup_logging(args)
        
        # Load mnemosyne configuration
        mnemosyne_config = load_mnemosyne_config(args.config)
        
        # Create and run pipeline
        with MnemosynePipeline(mnemosyne_config) as pipeline:
            # Validate setup first
            validation = pipeline.validate_setup()
            if validation['overall_status'] != 'valid':
                print("❌ Pipeline setup validation failed:")
                for key, value in validation.items():
                    if key != 'overall_status':
                        status = "✅" if value else "❌"
                        print(f"  {status} {key}: {value}")
                return 1
            
            print("✅ Pipeline setup validation passed")
            
            # Run training pipeline
            max_age_hours = args.max_age_hours if args.max_age_hours else None
            stats = pipeline.run_training_pipeline(max_training_data_age_hours=max_age_hours)
            
            # Print summary
            print("\n🎯 Training Pipeline Completed Successfully!")
            print(f"   Execution Time: {stats.get('execution_time_seconds', 0):.1f} seconds")
            print(f"   Training Samples: {stats.get('training', {}).get('training_samples', 'N/A')}")
            print(f"   Features Used: {stats.get('preprocessing', {}).get('final_features', 'N/A')}")
            print(f"   Artifact Upload: {len(stats.get('artifact_management', {}).get('upload', {}).get('uploaded_files', {}))} files")
            print(f"   Cleanup: {stats.get('cleanup', {}).get('deleted_count', 0)} old files deleted")
            
            return 0
            
    except Exception as e:
        print(f"❌ Training failed: {e}")
        if getattr(args, 'verbose', False):
            import traceback
            traceback.print_exc()
        return 1


def cmd_validate(args) -> int:
    """Validate mnemosyne pipeline setup."""
    try:
        setup_logging(args)
        
        # Load configuration
        mnemosyne_config = load_mnemosyne_config(args.config)
        
        # Create pipeline for validation
        with MnemosynePipeline(mnemosyne_config) as pipeline:
            validation = pipeline.validate_setup()
            
            print("🔍 Mnemosyne Pipeline Setup Validation")
            print("=" * 50)
            
            for key, value in validation.items():
                if key == 'overall_status':
                    status_emoji = {
                        'valid': '✅',
                        'partial': '⚠️',
                        'invalid': '❌'
                    }.get(value, '❓')
                    print(f"{status_emoji} Overall Status: {value.upper()}")
                elif key != 'error':
                    status_emoji = "✅" if value else "❌"
                    print(f"{status_emoji} {key.replace('_', ' ').title()}: {value}")
            
            if 'error' in validation:
                print(f"❌ Error: {validation['error']}")
                return 1
            
            if validation['overall_status'] == 'valid':
                print("\n🎉 Pipeline is ready for training!")
                return 0
            else:
                print("\n⚠️  Please fix the issues above before training.")
                return 1
                
    except Exception as e:
        print(f"❌ Validation failed: {e}")
        if getattr(args, 'verbose', False):
            import traceback
            traceback.print_exc()
        return 1


def cmd_status(args) -> int:
    """Check mnemosyne pipeline status."""
    try:
        setup_logging(args)
        
        # Load configuration
        mnemosyne_config = load_mnemosyne_config(args.config)
        
        # Create pipeline for status check
        with MnemosynePipeline(mnemosyne_config) as pipeline:
            status = pipeline.get_pipeline_status()
            
            print("📊 Mnemosyne Pipeline Status")
            print("=" * 40)
            print(f"Timestamp: {status['timestamp']}")
            print(f"Health: {status['pipeline_health']}")
            
            print("\n💾 Storage Usage:")
            storage = status['storage_usage']
            print(f"  Training Data: {storage['training_data']['file_count']} files, {storage['training_data']['total_size_mb']:.1f} MB")
            print(f"  Models: {storage['models']['file_count']} files, {storage['models']['total_size_mb']:.1f} MB")
            print(f"  Total: {storage['total_size_mb']:.1f} MB")
            
            print("\n🤖 Recent Models:")
            models = status['recent_models'][:5]  # Show last 5
            if models:
                for model in models:
                    print(f"  • {model['name']} ({model['size_mb']:.1f} MB) - {model['last_modified']}")
            else:
                print("  No recent models found")
            
            return 0
            
    except Exception as e:
        print(f"❌ Status check failed: {e}")
        if getattr(args, 'verbose', False):
            import traceback
            traceback.print_exc()
        return 1


def cmd_cleanup(args) -> int:
    """Clean up old training data and models."""
    try:
        setup_logging(args)
        
        # Load configuration
        mnemosyne_config = load_mnemosyne_config(args.config)
        
        # Create pipeline for cleanup
        with MnemosynePipeline(mnemosyne_config) as pipeline:
            
            if args.target == 'all' or args.target == 'training':
                print("🧹 Cleaning up old training data...")
                cleanup_stats = pipeline._data_loader.delete_old_training_data(args.max_age_hours)
                print(f"   Training data cleanup: {cleanup_stats['deleted_count']} files deleted, {cleanup_stats['remaining_count']} remaining")
            
            if args.target == 'all' or args.target == 'models':
                print("🧹 Cleaning up old models...")
                cleanup_stats = pipeline._artifact_manager.cleanup_old_models(args.max_age_days)
                print(f"   Model cleanup: {cleanup_stats['deleted_count']} models deleted, {cleanup_stats['remaining_count']} remaining")
            
            print("✅ Cleanup completed")
            return 0
            
    except Exception as e:
        print(f"❌ Cleanup failed: {e}")
        if getattr(args, 'verbose', False):
            import traceback
            traceback.print_exc()
        return 1


def cmd_list_models(args) -> int:
    """List available model artifacts."""
    try:
        setup_logging(args)
        
        # Load configuration
        mnemosyne_config = load_mnemosyne_config(args.config)
        
        # Create pipeline
        with MnemosynePipeline(mnemosyne_config) as pipeline:
            models = pipeline._artifact_manager.list_existing_models(
                max_age_days=args.max_age_days if args.recent else None
            )
            
            print("🤖 Model Artifacts")
            print("=" * 30)
            
            if not models:
                print("No models found")
                return 0
            
            for model in models:
                print(f"📁 {model['name']}")
                print(f"   Size: {model['size_mb']:.1f} MB")
                print(f"   Path: {model['remote_path']}")
                print(f"   Modified: {model['last_modified']}")
                print()
            
            return 0
            
    except Exception as e:
        print(f"❌ Failed to list models: {e}")
        if getattr(args, 'verbose', False):
            import traceback
            traceback.print_exc()
        return 1


def create_parser() -> argparse.ArgumentParser:
    """Create the main argument parser."""
    parser = argparse.ArgumentParser(
        prog="mnemosyne",
        description="Mnemosyne ML trainer pipeline for network anomaly detection"
    )
    
    # Global arguments
    parser.add_argument(
        "-c", "--config",
        type=str,
        default="mnemosyne-config.yaml",
        help="Path to mnemosyne configuration file (default: mnemosyne-config.yaml)"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )
    
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Set logging level (default: INFO)"
    )
    
    # Subcommands
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Train command
    train_parser = subparsers.add_parser("train", help="Run the training pipeline")
    train_parser.add_argument(
        "--max-age-hours",
        type=int,
        help="Maximum age of training data to use (hours)"
    )
    train_parser.set_defaults(func=cmd_train)
    
    # Validate command
    validate_parser = subparsers.add_parser("validate", help="Validate pipeline setup")
    validate_parser.set_defaults(func=cmd_validate)
    
    # Status command
    status_parser = subparsers.add_parser("status", help="Check pipeline status")
    status_parser.set_defaults(func=cmd_status)
    
    # Cleanup command
    cleanup_parser = subparsers.add_parser("cleanup", help="Clean up old data and models")
    cleanup_parser.add_argument(
        "target",
        choices=["all", "training", "models"],
        default="all",
        help="What to clean up (default: all)"
    )
    cleanup_parser.add_argument(
        "--max-age-hours",
        type=int,
        default=24,
        help="Maximum age for training data cleanup (hours, default: 24)"
    )
    cleanup_parser.add_argument(
        "--max-age-days",
        type=int,
        default=30,
        help="Maximum age for model cleanup (days, default: 30)"
    )
    cleanup_parser.set_defaults(func=cmd_cleanup)
    
    # List models command
    list_parser = subparsers.add_parser("list-models", help="List available model artifacts")
    list_parser.add_argument(
        "--recent",
        action="store_true",
        help="Only show models from the last 30 days"
    )
    list_parser.add_argument(
        "--max-age-days",
        type=int,
        default=30,
        help="Maximum age for recent models filter (days, default: 30)"
    )
    list_parser.set_defaults(func=cmd_list_models)
    
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    """Main entry point for the mnemosyne CLI."""
    parser = create_parser()
    args = parser.parse_args(argv)
    
    if not hasattr(args, 'func'):
        parser.print_help()
        return 1
    
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())