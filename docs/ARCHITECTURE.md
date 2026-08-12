# Architecture and trust boundary

Argus Community has one supported data path:

```text
network interface
  → Scapy packet callback
  → canonical observed packet fields
  → bounded bidirectional flow aggregation
  → protocol metadata and deterministic signatures
  → optional validated user-trained logistic baseline
  → bounded in-memory completed-flow store
  → authenticated loopback REST API
  → polling local dashboard
```

## State limits

| State | Limit | Disposal |
| --- | ---: | --- |
| Active flows | 10,000 | Oldest flow is finalized when capacity is reached |
| Payload prefixes | 4 × 2,048 bytes per flow | Released when the flow is finalized |
| Completed results | 1,000 | Oldest result is evicted |
| Flow lifetime | 5-second idle timeout by default | TCP FIN/RST can finalize earlier |

The supported runtime does not write packet-capture files. Process restart clears
all flow and result state.

## Identity and direction

A flow key is the normalized pair of endpoint `(IP, port)` values plus transport
protocol. The first observed packet establishes display direction; reverse packets
contribute to outbound counters for that flow. This is observation-level flow
tracking, not TCP stream reassembly.

## Decision semantics

Argus emits only two public analysis states:

- `UNASSESSED`: no signature or configured baseline crossed its threshold.
- `SUSPICIOUS`: signature evidence exists or the configured baseline crossed its threshold.

`UNASSESSED` is not a benign classification. The result includes observed fields,
signature evidence, runtime health, and decision provenance. No absent detector is
represented by a zero score.

## Security boundary

The API and dashboard bind to loopback by default. A launcher-generated token is
exchanged for an HttpOnly, same-site session cookie; API clients may use
`X-API-Key`. Capture privileges do not imply permission to expose the API remotely.

Pretrained weights, advanced research models, archived captures, and automated
host enforcement are not part of this repository. The optional public baseline
loads only a strict JSON schema from the path explicitly named by the operator;
it never discovers files, auto-trains, or deserializes executable objects.
