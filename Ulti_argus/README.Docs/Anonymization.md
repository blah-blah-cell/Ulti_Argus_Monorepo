# Anonymization

Argus_V includes a couple of small primitives intended for consistent, privacy-preserving aggregation.

## Salted IP hashing

Use `hash_ip()` to derive a stable identifier for an IP address without storing or logging the raw IP.

```python
from argus_v.oracle_core.anonymize import hash_ip

ip_id = hash_ip("192.0.2.1", salt="your-long-random-salt")
```

Notes:

- hashing uses an HMAC (SHA-256) with a required, non-trivial salt
- output is intentionally one-way (not reversible)

## Timestamp rounding

Use `round_datetime()` to bucket timestamps into fixed windows.

```python
from datetime import datetime, timezone
from argus_v.oracle_core.anonymize import round_datetime

bucket = round_datetime(datetime.now(tz=timezone.utc), resolution_seconds=60)
```
