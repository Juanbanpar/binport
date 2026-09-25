# CLI output contract

`tests/output_contract.rs` compares the complete text and JSON output, byte for
byte, against these files. Tests invoke only binport, with an empty PATH and
stable relative fixture paths; there is no masking of output fields.

The cases cover compatible, incompatible, incomplete/unknown, weak requirements
(available and unavailable), weak symbols with mandatory versions, CPU mismatch,
an explicit glibc ceiling, incompatibility taking precedence over unknown, and
analysis errors. Exact symbol causes, schema fields, ordering, nulls, warnings,
scope text and stdout/stderr placement are part of the snapshots. Each case also
checks all four combinations of default/`inspect` syntax and inspection/CI mode,
with exit codes fixed independently of the snapshots.

Ordinary tests never create or update a snapshot. For an intentional contract
change, run from the project root:

```sh
BINPORT_UPDATE_GOLDENS=1 cargo test --locked --test output_contract
cargo test --locked --test output_contract
```

Review every changed file, particularly symbol causes and compatibility results.
Updating snapshots does not authorize a schema change: incompatible JSON field,
type or meaning changes still require a schema-version decision. Updates are
rejected when the `CI` environment variable is present. Existing semantic tests
remain independent of these golden files.
