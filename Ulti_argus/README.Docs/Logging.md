# Logging

Argus_V provides a small structured logging layer with privacy guardrails.

## Configure

```python
from argus_v.oracle_core.logging import configure_logging, log_event

logger = configure_logging(level="INFO")
log_event(logger, "startup", version="0.1.0")
```

## Privacy guardrails

The logging module:

- redacts common secret-bearing keys (`token`, `password`, `api_key`, ...)
- scrubs obvious PII patterns from messages (email addresses, IPv4 literals)

Use `log_event()` with structured fields rather than interpolating secrets into the log message.

## Pi-friendly defaults

The default log level is `INFO`, with noisy third-party libraries (e.g. `urllib3`) forced to `WARNING`.
