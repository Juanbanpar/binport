# CLI snapshots

`output_contract.rs` compares complete text and JSON output with these snapshots,
including exit codes and stdout/stderr placement.

Update snapshots only for an intentional CLI contract change:

```sh
BINPORT_UPDATE_GOLDENS=1 cargo test --locked --test output_contract
cargo test --locked --test output_contract
```

Review every changed file. CI rejects snapshot updates. A snapshot change does not
by itself authorize a JSON schema change.
