# Ulti_Argus Monorepo

[![CI](https://github.com/blah-blah-cell/Ulti_Argus_Monorepo/actions/workflows/ci.yml/badge.svg)](https://github.com/blah-blah-cell/Ulti_Argus_Monorepo/actions/workflows/ci.yml)

This repository is the central monorepo containing the Ulti_Argus ecosystem. It is divided into two main sub-projects:

## 1. [Ulti_argus](./Ulti_argus/)
The primary threat intelligence, access control, and orchestration platform. This component handles the high-level security models, plugins, and AI-driven analysis.

## 2. [DeepPacketSentinel](./DeepPacketSentinel/)
A next-generation Deep Packet Inspection (DPI) security engine built in Rust. It utilizes eBPF/XDP for high-speed packet capture and filtering in the Linux kernel (Data Plane) and streams flow metadata to userspace for deep learning classification and policy enforcement (Inference Plane).

---

### Setup & Development
Each sub-project maintains its own dependencies and build instructions. Please refer to their respective README files for detailed documentation:
* [Ulti_argus Documentation](./Ulti_argus/README.md)
* [DeepPacketSentinel Documentation](./DeepPacketSentinel/README.md)
