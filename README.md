# MojoAttention-CPU

[![Foundation Quality](https://github.com/MuhammadImaz/MojoAttention-CPU/actions/workflows/foundation-quality.yml/badge.svg)](https://github.com/MuhammadImaz/MojoAttention-CPU/actions/workflows/foundation-quality.yml)

An evidence-driven portfolio implementation of CPU causal attention across a protected PyTorch reference and Mojo backends.

The current foundation provides deterministic bootstrap checks and a read-only host preflight. See [docs/setup.md](docs/setup.md).

```bash
scripts/install-uv.sh
scripts/bootstrap.sh --sync
scripts/bootstrap.sh --check
scripts/run.sh mojoattention preflight --mode broad --json -
scripts/run.sh max --version
```
