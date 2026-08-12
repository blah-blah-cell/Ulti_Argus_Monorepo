# Repository guidance

The supported product surface is the Python package in `Ulti_argus/src`, the
FastAPI service in `web/api`, and the static dashboard in `web/public`.

Changes must preserve these rules:

- Never fabricate packets, scores, alerts, successful backend actions, or benchmarks.
- Keep capture, payload, and result state explicitly bounded.
- Report unavailable capture backends and incomplete evidence honestly.
- Keep API and dashboard loopback-only by default.
- Require authentication for capture control and traffic details.
- Never commit captures, credentials, datasets, model artifacts, or build output.
- Add focused tests for changed runtime and failure behavior.

Run the checks documented in `README.md` before publishing changes.
