# Configuration

Argus_V uses a YAML configuration file, loaded via `argus_v.oracle_core.config.load_config()`.

## Load a config

```python
from argus_v.oracle_core.config import load_config

cfg = load_config("configs/sample_free_tier.yaml")
print(cfg.runtime.dry_run)
```

## Schema overview

Top-level keys:

- `sampling`: window configuration used by collectors/aggregators.
- `interfaces`: enable/disable individual integrations.
- `firebase`: Firebase connection details (free-tier friendly REST style config).
- `github`: GitHub API access configuration.
- `blacklist`: cadence + sources for blacklist syncing.
- `runtime`: runtime flags like `dry_run` and `log_level`.

## Secrets

Sample configs use environment variable placeholders (e.g. `${GITHUB_TOKEN}`). The loader expands these and raises if a referenced environment variable is not set.

## How other components consume config

Components should:

1. Load config once at startup.
2. Use `cfg.interfaces` toggles to decide whether to activate an integration.
3. Never log secrets; use `cfg.to_safe_dict()` for logging/debugging.

```python
from argus_v.oracle_core.config import load_config
from argus_v.oracle_core.logging import configure_logging, log_event

cfg = load_config("/etc/argus_v/config.yaml")
logger = configure_logging(level=cfg.runtime.log_level)

log_event(logger, "config_loaded", config=cfg.to_safe_dict())
```
