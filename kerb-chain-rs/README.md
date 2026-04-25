# kerb-chain (Rust port)

Single-binary Rust port of the Python `kerb_chain` orchestrator. Same
YAML playbook format, same `journal.json` shape on disk, same
condition language. Distributable as a static `kerb-chain` binary
alongside or instead of the Python implementation.

```bash
cd kerb-chain-rs
cargo build --release
./target/release/kerb-chain --help
```

The Python and Rust versions are intentionally interchangeable per
playbook run — the Python side ships the bundled `standard.yaml`
library; the Rust side reads any compatible YAML playbook.

See the parent repo's wiki for usage; CLI flags match the Python CLI.
