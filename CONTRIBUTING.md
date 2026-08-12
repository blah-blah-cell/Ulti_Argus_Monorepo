# Contributing

Small, reviewable changes are preferred.

1. Create a branch from `main`.
2. Install the development extra: `python -m pip install -e "./Ulti_argus[dev]"`.
3. Add focused tests for changed behavior.
4. Run the checks in `README.md`.
5. Confirm no model, dataset, capture, credential, generated output, or undisclosed implementation is present.
6. Open a pull request describing runtime behavior, failure behavior, and validation evidence.

Security-sensitive changes must preserve fail-closed behavior. Synthetic data is allowed only in tests and benchmarks that are explicitly labeled; it must not be substituted for live capture or real model output.
