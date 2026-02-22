# Mnemosyne Trainer Pipeline

Mnemosyne is the machine learning training pipeline component of the Argus_V system, responsible for training IsolationForest models on aggregated network flow data for anomaly detection.

## Overview

The Mnemosyne pipeline automates the entire ML model training lifecycle:

1. **Data Loading**: Fetches aggregated CSV flows from Firebase Storage/Realtime DB
2. **Preprocessing**: Applies log scaling, feature normalization, and outlier detection
3. **Model Training**: Trains IsolationForest models with hyperparameter tuning
4. **Artifact Management**: Serializes and uploads models to Firebase Storage
5. **Cleanup**: Removes old training data and model artifacts
6. **Monitoring**: Provides structured logging and status monitoring

## Architecture

### Core Components

```
mnemosyne/
├── __init__.py              # Module initialization
├── config.py                # Configuration schema and validation
├── data_loader.py           # Firebase data loading functionality
├── preprocessing.py         # Feature preprocessing pipeline
├── trainer.py              # IsolationForest training and evaluation
├── artifact_manager.py     # Model serialization and Firebase upload
├── pipeline.py             # Main orchestration pipeline
└── cli.py                  # Command-line interface
```

### Configuration

The pipeline uses YAML configuration files with the following structure:

```yaml
firebase:
  project_id: your-project-id
  storage_bucket: your-project-id.appspot.com
  service_account_path: ~/.config/gcloud/service-account.json
  training_data_path: flows/training
  model_output_path: models
  cleanup_threshold_hours: 24

preprocessing:
  log_transform_features: [bytes_in, bytes_out, packets_in, packets_out, duration]
  feature_normalization_method: standard
  contamination_auto_tune: true
  contamination_range: [0.01, 0.1]
  min_samples_for_training: 1000
  max_model_size_mb: 100

training:
  random_state: 42
  n_estimators_range: [50, 200]
  max_samples_range: [0.5, 1.0]
  bootstrap_options: [true, false]
  validation_split: 0.2
  cross_validation_folds: 3
```

## Features

### Data Loading
- **Firebase Integration**: Uses service account with free tier restrictions
- **Age-based Filtering**: Only loads data newer than specified hours
- **Data Validation**: Ensures CSV files have required columns
- **Batch Processing**: Efficiently handles large datasets
- **Error Recovery**: Continues processing even if individual files fail

### Preprocessing Pipeline
- **Feature Preparation**: Extracts relevant network flow features
- **Log Transformation**: Applies log1p transformation to reduce skewness
- **Outlier Detection**: Uses IQR method to identify and remove extreme outliers
- **Feature Normalization**: StandardScaler or RobustScaler based on data characteristics
- **Contamination Tuning**: Automatically tunes IsolationForest contamination parameter

### Model Training
- **Hyperparameter Optimization**: Grid search with cross-validation
- **Multiple Algorithms**: Tests different IsolationForest configurations
- **Model Validation**: Evaluation metrics including anomaly rate and AUC
- **Reproducibility**: Fixed random seeds for consistent results
- **Performance Monitoring**: Tracks training time and resource usage

### Artifact Management
- **Model Serialization**: Pickle-based serialization with metadata
- **Size Validation**: Ensures artifacts stay under size limits
- **Firebase Upload**: Automated upload to Google Cloud Storage
- **Metadata Tracking**: Comprehensive model metadata and versioning
- **Cleanup Automation**: Removes old artifacts based on retention policies

## Installation

1. **Install Dependencies**:
   ```bash
   pip install -e .[dev]
   ```

2. **Configure Firebase**:
   - Create a Firebase project
   - Enable Cloud Storage
   - Generate service account credentials
   - Download JSON key file

3. **Setup Configuration**:
   ```bash
   cp mnemosyne-config.example.yaml mnemosyne-config.yaml
   # Edit the configuration file with your settings
   ```

## Usage

### Command Line Interface

```bash
# Validate pipeline setup
python -m argus_v.mnemosyne.cli validate -c mnemosyne-config.yaml

# Run training pipeline
python -m argus_v.mnemosyne.cli train -c mnemosyne-config.yaml --max-age-hours 168

# Check pipeline status
python -m argus_v.mnemosyne.cli status -c mnemosyne-config.yaml

# Clean up old data
python -m argus_v.mnemosyne.cli cleanup all -c mnemosyne-config.yaml

# List existing models
python -m argus_v.mnemosyne.cli list-models -c mnemosyne-config.yaml --recent
```

### Python API

```python
from argus_v.mnemosyne.config import load_mnemosyne_config
from argus_v.mnemosyne.pipeline import MnemosynePipeline

# Load configuration
config = load_mnemosyne_config('mnemosyne-config.yaml')

# Run pipeline
with MnemosynePipeline(config) as pipeline:
    # Validate setup
    validation = pipeline.validate_setup()
    
    # Run training
    stats = pipeline.run_training_pipeline(max_training_data_age_hours=168)
    
    # Check status
    status = pipeline.get_pipeline_status()
```

## GitHub Actions Workflow

The weekly training pipeline is automated via `.github/workflows/mnemosyne-weekly-training.yml`:

### Workflow Features
- **Scheduled Execution**: Runs every Monday at 02:00 UTC
- **Setup Validation**: Validates configuration and Firebase connectivity
- **Data Availability Check**: Ensures sufficient training data exists
- **Automated Training**: Runs full pipeline with error handling
- **Failure Notifications**: Reports pipeline failures with details
- **Artifact Management**: Uploads training results and statistics

### Required GitHub Variables
```
MNEMOSYNE_CONFIG_PATH=mnemosyne-config.yaml
FIREBASE_PROJECT_ID=your-project-id
FIREBASE_STORAGE_BUCKET=your-project-id.appspot.com
```

### Required GitHub Secrets
```
SERVICE_ACCOUNT_PATH=path/to/service-account.json
```

## Testing

Run the comprehensive test suite:

```bash
# Run all mnemosyne tests
pytest tests/mnemosyne/ -v

# Run specific test module
pytest tests/mnemosyne/test_config.py -v

# Run with coverage
pytest tests/mnemosyne/ --cov=argus_v.mnemosyne --cov-report=html
```

### Test Coverage
- **Configuration**: Validates YAML parsing and parameter validation
- **Data Loading**: Tests Firebase connectivity and CSV processing
- **Preprocessing**: Validates feature engineering and transformation
- **Model Training**: Tests hyperparameter tuning and evaluation
- **Artifact Management**: Validates serialization and upload functionality
- **Pipeline Orchestration**: Tests end-to-end workflow execution

## Monitoring and Logging

### Structured Logging
All operations use structured JSON logging with privacy filtering:

```json
{
  "ts": "2024-01-01T10:00:00Z",
  "level": "INFO",
  "logger": "argus_v.mnemosyne.pipeline",
  "message": "mnemosyne_training_pipeline_completed",
  "fields": {
    "execution_time_seconds": 1247.5,
    "training_samples": 15420,
    "anomaly_rate": 0.035
  }
}
```

### Key Metrics
- **Training Statistics**: Sample counts, feature dimensions, processing time
- **Model Performance**: Anomaly detection rates, AUC scores, contamination values
- **System Health**: Storage usage, Firebase connectivity, data freshness
- **Pipeline Status**: Success/failure rates, error patterns, resource usage

## Deployment

### Local Development
1. Clone repository and install dependencies
2. Configure Firebase credentials
3. Run validation and test pipeline
4. Execute training pipeline locally

### Production Deployment
1. Use GitHub Actions workflow for automated training
2. Configure GitHub variables and secrets
3. Monitor workflow execution and notifications
4. Use CLI commands for manual operations and troubleshooting

### Raspberry Pi Deployment
Mnemosyne is designed to work on resource-constrained environments:

- **Memory Efficient**: Processes data in batches to minimize memory usage
- **Low CPU Impact**: Uses single-threaded operations for consistency
- **Storage Optimization**: Automatically cleans up old data and models
- **Network Friendly**: Batches Firebase operations to minimize bandwidth

## Security Considerations

### Data Protection
- **Service Account Restrictions**: Use least-privilege service accounts
- **Data Anonymization**: Raw flow data contains anonymized IPs
- **Encryption**: All data transmission uses HTTPS/TLS
- **Access Control**: Firebase Security Rules restrict access

### Artifact Security
- **Model Size Limits**: Prevents resource exhaustion attacks
- **Metadata Scrubbing**: Removes sensitive information from logs
- **Version Control**: Maintains audit trail of model versions
- **Backup Strategy**: Regular cleanup prevents data accumulation

## Troubleshooting

### Common Issues

1. **Firebase Authentication Failed**
   - Verify service account JSON file exists and is readable
   - Check project ID and storage bucket configuration
   - Ensure service account has necessary permissions

2. **Insufficient Training Data**
   - Check that retina collectors are uploading data to Firebase
   - Verify training data path configuration
   - Adjust max_age_hours parameter for training

3. **Model Size Exceeds Limit**
   - Reduce model complexity by adjusting n_estimators_range
   - Increase max_model_size_mb if necessary
   - Consider feature selection to reduce dimensionality

4. **Training Timeout**
   - Reduce cross_validation_folds for faster training
   - Limit n_estimators_range to smaller ranges
   - Check system resources and consider horizontal scaling

### Debug Commands

```bash
# Validate configuration and Firebase connectivity
python -m argus_v.mnemosyne.cli validate -v

# Check training data availability
python -m argus_v.mnemosyne.cli status -v

# List recent training data files
python -m argus_v.mnemosyne.cli list-data --recent

# Test preprocessing pipeline
python -c "from argus_v.mnemosyne.preprocessing import FlowPreprocessor; ..."

# Manual model training with debugging
python -c "
import logging
logging.basicConfig(level=logging.DEBUG)
from argus_v.mnemosyne.pipeline import MnemosynePipeline
..."
```

## Performance Optimization

### Training Performance
- **Data Subsampling**: Use max_age_hours to limit data volume
- **Feature Selection**: Reduce feature dimensionality
- **Batch Processing**: Process data in chunks to manage memory
- **Parallel Training**: Use cross_validation_folds for parallel processing

### Storage Optimization
- **Automatic Cleanup**: Configure appropriate retention policies
- **Compression**: Models are automatically compressed
- **Metadata Management**: Keep metadata minimal and relevant
- **Storage Monitoring**: Regular usage analysis and cleanup

## Future Enhancements

### Planned Features
- **Multi-Model Ensemble**: Train multiple algorithms and ensemble results
- **Real-time Inference**: Add real-time anomaly detection endpoint
- **Automated Retraining**: Dynamic retraining based on performance drift
- **Advanced Preprocessing**: Additional feature engineering techniques
- **Model Interpretability**: Feature importance and explanation tools

### Integration Points
- **Grafana Dashboard**: Real-time monitoring and alerting
- **Slack Notifications**: Automated failure notifications
- **Model Registry**: Integration with MLflow or similar
- **API Endpoints**: REST API for model serving and status

## Contributing

1. Follow existing code patterns and style
2. Add comprehensive unit tests for new features
3. Update documentation for configuration changes
4. Ensure backward compatibility with existing configurations
5. Test on both development and production-like environments

## License

Proprietary - Argus_V Team