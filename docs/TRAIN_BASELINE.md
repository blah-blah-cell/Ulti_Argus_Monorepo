# Train your own baseline

Argus Community includes a compact logistic classifier so operators can verify
the complete capture-to-model path without receiving anyone else's weights or
data. It is a baseline, not a claim of state-of-the-art detection.

## What the model uses

The `argus.flow-baseline.v1` schema contains twelve numeric, flow-close features:

| Group | Features |
| --- | --- |
| Volume | log total bytes, log total packets |
| Time | log duration, log mean/std inter-arrival time |
| Size | log mean/std packet size |
| Direction | inbound packet ratio, inbound byte ratio |
| TCP | SYN, FIN, and RST ratios |

IP addresses, payload bytes, hostnames, and labels are never model inputs. Fixed
log/ratio transforms run before normalization. Mean and scale are learned only
from the training partition and stored with the weights.

## 1. Collect real observations

Run Argus on a network you are authorized to monitor. Generate traffic in a
controlled experiment where the ground truth is known, stop capture so active
flows are finalized, then export the recent observations:

```bash
export ARGUS_API_KEY='the-value-in-your-.env'
curl -fsS -H "X-API-Key: $ARGUS_API_KEY" \
  "http://127.0.0.1:8000/api/detect/flows?limit=500" > flows.json

python -m argus_v.baseline prepare \
  --input flows.json \
  --output labelled-flows.csv
```

The API keeps only a bounded recent window. Repeat controlled sessions and merge
CSV rows if you need more observations. Do not commit exported flows: timing and
traffic metadata can still be sensitive.

## 2. Label from ground truth

Fill the `label` column with either:

- `0`, `benign`, or `normal`
- `1`, `attack`, `malicious`, or `suspicious`

Use experiment logs, host telemetry, or a known replay manifest. Do **not** copy
Argus signature output into the label column; that would teach the model to mimic
the existing rules and make evaluation circular.

At least ten rows, two per class, are required by the tool. In practice, use
substantially more data from multiple capture periods and devices.

## 3. Train

Write the artifact outside the repository:

```bash
mkdir -p "$HOME/.local/share/argus"
python -m argus_v.baseline train \
  --csv labelled-flows.csv \
  --output "$HOME/.local/share/argus/baseline.argus-baseline.json" \
  --epochs 400 \
  --threshold 0.5
```

Training is deterministic for a fixed `--seed`. It uses class-balanced logistic
loss, L2 regularization, and a stratified holdout. The command prints holdout
accuracy, precision, recall, and F1.

The built-in random holdout is only a smoke evaluation. For a credible result,
train and test on different capture days, devices, and attack families, and
report false alerts per hour plus precision/recall. Never tune on the final test
set.

## 4. Enable it

Set an absolute path in `.env`:

```dotenv
ARGUS_BASELINE_MODEL=/home/you/.local/share/argus/baseline.argus-baseline.json
```

Restart `./start.sh`, then verify `/api/system` reports:

```json
{"components":{"baseline_model":{"status":"loaded","model_id":"..."}}}
```

If the path is absent, Argus continues with signatures only. If the artifact is
malformed or schema-incompatible, it is rejected and the dashboard reports that
state; Argus never substitutes random weights.

## Runtime interpretation

- Scores at or above the stored threshold produce `SUSPICIOUS`.
- Scores below it remain `UNASSESSED`, not benign or safe.
- Signature evidence can independently produce `SUSPICIOUS`.
- Each model-backed result includes the artifact hash prefix, threshold, schema,
  score, and decision time.

Artifacts are bounded JSON—not pickle—so loading cannot execute serialized Python
objects. Treat them as operational inputs and keep them out of Git.
