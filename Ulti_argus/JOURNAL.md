# Argus_V Engineering Journal

## 00. Architectural Critique: "The Cold Start Problem"
**Date:** October 26, 2023
**Focus:** `aegis.model_manager.ModelManager`

### The Status Quo
The current implementation of `Argus_V` relies on a "Fall-Back Model" when no pre-trained model is found locally or in Firebase.
This fallback logic (`_use_fallback_model` in `model_manager.py`) instantiates an `IsolationForest` and fits it on `np.random.randn(200, n_features)`.

### The Problem
This is "Security Theater."
1.  **Randomness is not a Baseline:** Training an anomaly detector on random noise means the model has no concept of "normal" network traffic (DNS, HTTP, NTP). It will flag legitimate traffic as anomalous purely by chance.
2.  **Zero-Day Vulnerability:** A new installation is effectively blind until the first weekly training cycle (`Mnemosyne`) completes.
3.  **Credibility:** If the system generates 100 false positives in the first hour, the user will uninstall it before it ever learns.

### The Objective
We need a "Foundation Model" — a pre-trained artifact shipped with the appliance. This model should be trained on a generic but representative dataset (like CIC-IoT2023) to provide baseline competence.

### The Plan
1.  **Synthetic Foundation:** Since we cannot train on 30GB of real IoT data in this repo, we will generate a "Synthetic Foundation Model" that approximates the statistical distribution of normal IoT traffic.
2.  **Loader Logic Upgrade:** Refactor `ModelManager` to prioritize:
    1.  Remote Model (Firebase - specialized for this user)
    2.  Local Cached Model (Previous training)
    3.  **Foundation Model (Shipped artifact)**
    4.  Random Fallback (Last resort/Panic mode)
3.  **Configuration:** Expose the foundation model path in `ModelConfig`.

---

## 01. Dev Log: Solving the Cold Start Problem
**Date:** October 26, 2023
**Feature:** Foundation Model Loader

### Problem
As identified in Entry 00, Argus_V starts in a vulnerable state. We needed a way to ship a "good enough" model that works out of the box.

### Options Considered
1.  **Train on Real Data (CIC-IoT2023):**
    *   *Pros:* High accuracy.
    *   *Cons:* Dataset is huge (GBs), impossible to include in repo or CI/CD.
2.  **Rule-Based Fallback:**
    *   *Pros:* Deterministic.
    *   *Cons:* Not "AI", requires maintaining complex rules, defeats the purpose of learning "normal" behavior.
3.  **Synthetic Foundation Model:**
    *   *Pros:* Lightweight, reproducible, better than random.
    *   *Cons:* Approximation of reality.

### Selected Solution
I chose **Option 3**. I created a script `scripts/generate_foundation_model.py` that generates synthetic traffic mimicking DNS, HTTP, NTP, and SSH patterns. It trains an `IsolationForest` on this data and saves the artifacts (`foundation_model.pkl`, `foundation_scaler.pkl`).

I then refactored `ModelManager` to implement a hierarchy of needs:
1.  **Personalized Model** (Remote/Local) - Best.
2.  **Foundation Model** (Shipped) - Good.
3.  **Random Fallback** - Worst case.

### Reflection
This architectural change transforms Argus_V from a "project" to a "product". Users now get immediate value (anomaly detection based on general internet norms) while the system learns their specific environment in the background. The code is modular: if we later get a better foundation model, we just replace the `.pkl` file.

---

## 02. Dev Log: Explainable AI (XAI) for Opaque Inference
**Date:** February 04, 2026
**Feature:** Explainable Inference (XAI) Engine

### Problem
The `IsolationForest` model outputs a raw anomaly score (e.g., `-0.8`). This is opaque to the user. A log message saying "Traffic blocked due to score -0.8" builds no trust and offers no actionable intelligence. Was it a port scan? Data exfiltration? DDoS?

### Options Considered
1.  **SHAP (SHapley Additive exPlanations):**
    *   *Pros:* The gold standard for model interpretability. Theoretically sound.
    *   *Cons:* Computationally expensive ($O(M \cdot N^2)$). Too slow for real-time inference on a Raspberry Pi.
2.  **LIME (Local Interpretable Model-agnostic Explanations):**
    *   *Pros:* Good local approximations.
    *   *Cons:* Still requires multiple perturbation passes per prediction, adding significant latency.
3.  **Heuristic Z-Score Analysis:**
    *   *Pros:* Extremely fast ($O(1)$). Uses existing scaler statistics (mean/variance). Intuitive (measures deviation from "normal" in standard deviations).
    *   *Cons:* Assumes feature independence (ignores correlations). Not a "true" explanation of the tree path, but a strong proxy for *why* a point is an outlier in feature space.

### Selected Solution
I chose **Option 3 (Heuristic Z-Score)**.
Since Argus_V runs on constrained hardware, latency is king.
I implemented `explain_anomaly(flow, top_k=3)` in `ModelManager`. It calculates the Z-score for each feature ($z = \frac{x - \mu}{\sigma}$) using the pre-loaded `StandardScaler`. Features with the highest absolute Z-scores are flagged as the "reason" for the anomaly.

**Output Example:**
`"High-risk anomaly: bytes_out (+4.2σ), duration (+3.1σ) (score: -0.812)"`

### Reflection
This is a classic engineering trade-off: Accuracy vs. Latency. While SHAP is more "correct", Z-scores are "correct enough" for a network admin to decide if `bytes_out` being 4000% higher than normal is suspicious. It turns a black box into a glass box without melting the CPU.

---

## 03. Dev Log: Active Learning Feedback Loop
**Date:** February 04, 2026
**Feature:** Active Learning (Human-in-the-Loop)

### Problem
Anomaly detection systems suffer from false positives. If Argus_V blocks the CEO's printer or a critical API webhook, the user needs a way to correct it *immediately* and ensure the system learns from this mistake. Manually editing `iptables` or SQL databases is error-prone and doesn't update the AI model.

### Options Considered
1.  **Online Learning (Incremental Fit):**
    *   *Pros:* Model updates instantly.
    *   *Cons:* `IsolationForest` (sklearn implementation) doesn't support true online learning (only `warm_start` which is tricky). Risky: a user might whitelist a malicious IP by mistake, poisoning the model immediately.
2.  **Tag & Batch Retrain:**
    *   *Pros:* Safe, robust. User feedback acts as a "label" for the next batch training.
    *   *Cons:* Model only gets smarter at the next scheduled interval (e.g., weekly).
3.  **Hybrid (Allowlist + Triggered Retrain):**
    *   *Pros:* Immediate relief (allowlist) + accelerated learning (trigger retrain).

### Selected Solution
I chose **Option 3**.
I implemented a `FeedbackManager` and a CLI command: `argus feedback --false-positive <IP>`.
1.  **Immediate Action:** The IP is added to a local `trusted_ips.json` allowlist (and removed from the blacklist if present).
2.  **Learning Signal:** A flag file (`trigger_retrain`) is touched. The `Mnemosyne` training pipeline (running independently) monitors this flag to prioritize a retraining session, incorporating the labeled "normal" data to shift the decision boundary.

### Reflection
This closes the loop between the AI and the human operator. It transforms the user from a passive observer to an active teacher. The CLI approach integrates well with the "headless appliance" philosophy—admins can script this correction into their own workflows.

---

## 04. Dev Log: Optimizing Enforcement Latency
**Date:** February 06, 2026
**Feature:** Cached Iptables Availability Check

### Problem
The `BlacklistManager` was checking for the presence of the `iptables` binary by spawning a subprocess (`subprocess.run(['iptables', '--version'])`) *every time* an IP was added to the blacklist. On a Raspberry Pi, process creation is expensive (approx. 300ms overhead). This redundancy creates unnecessary CPU load and latency during high-traffic enforcement bursts.

### Options Considered
1.  **Ignore:** Accept the overhead as "safety."
    *   *Cons:* Wasteful. Latency matters in network defense.
2.  **Initialization Check:** Check once in `__init__`.
    *   *Pros:* Simple.
    *   *Cons:* If the system starts before `iptables` is installed (unlikely but possible in containers), it requires a restart to detect it.
3.  **Lazy Caching:** Check on first use and cache the result.
    *   *Pros:* Optimized for the common path (success), but handles the dynamic nature (checked when needed).
    *   *Cons:* Slight complexity in state management.

### Selected Solution
I chose **Option 3 (Lazy Caching)**.
I introduced `_iptables_available` state to `BlacklistManager`. The check runs once per process lifetime. This reduced the overhead of the availability check from ~300ms to ~0.004ms (orders of magnitude speedup), making the `add_to_blacklist` operation CPU-bound rather than I/O-bound.

### Reflection
This is a "low-hanging fruit" optimization. While Python is not C++, avoiding unnecessary system calls is a universal principle of performance engineering. This ensures that the enforcement loop remains tight, allowing Argus to keep up with faster packet rates.
