# Shared schema

`argus_v.oracle_core.schema` defines a minimal shared envelope for feature payloads.

```python
from datetime import datetime, timezone
from argus_v.oracle_core.schema import FeatureRecord

record = FeatureRecord(
    observed_at=datetime.now(tz=timezone.utc),
    source="github",
    features={"event": "push"},
)
print(record.as_dict())
```

Components are expected to reuse the shared keys when possible and add domain-specific keys in their own packages.
