# binport

`binport` inspects Linux ELF files without executing them. It reports declared ABI
requirements, compares them with distribution baselines, and identifies imported
symbols that raise the required glibc version.

## Install and use

Install from the project directory:

```sh
cargo install --path . --locked
```

Inspect a file:

```sh
binport ./myprogram
binport ./myprogram --target debian-12
binport ./myprogram --target ubuntu-22.04 --fail-incompatible
binport ./myprogram --glibc 2.31 --fail-incompatible
binport ./myprogram --target debian-12 --cpu x86-64-v2 --fail-incompatible
binport ./myprogram --json
```

Without `--target` or `--glibc`, binport reports all built-in releases. Repeat
`--target` to check multiple releases. `--glibc` checks only the glibc ceiling unless
combined with `--target`; `--glibc-max` is an alias. `inspect FILE` is an optional
subcommand alias, and `--help` lists all options. Use `--cpu` to declare target x86
ISA (`x86-64`, `x86-64-v2`, `x86-64-v3` or `x86-64-v4`); a distro release does not
identify the target machine's CPU.

Built-in targets: `ubuntu-20.04`, `ubuntu-22.04`, `ubuntu-24.04`, `debian-12`,
`debian-13` and `rhel-9`. Their ABI baselines and sources are in
[`data/distros.toml`](data/distros.toml).

## Results

Compatibility checks cover the ELF architecture and ABI, loader family and
interpreter, required glibc version, and declared x86 ISA requirements when `--cpu`
is supplied. `compatible` means these checks pass within that scope. It does not
guarantee the program will run: binport does not resolve dependencies or check kernel
requirements, deployment configuration, or undeclared CPU instructions.

The detailed deployment profiles are x86_64 and AArch64, 64-bit little-endian. Other
architectures and ABI variants can be inspected, but their compatibility is reported
as unknown. Binaries without section headers can have incomplete symbol-version
analysis and cannot receive a positive glibc verdict. RPATH and RUNPATH entries are
reported literally; binport does not resolve them.

Inspection exits 0 when analysis succeeds, regardless of the verdict. Add
`--fail-incompatible` to use these CI exit codes:

| Code | Result |
| --- | --- |
| 0 | All selected checks are compatible |
| 1 | At least one selected check is incompatible |
| 2 | Input, analysis, target or argument error |
| 3 | A required check is unknown |

Without an explicit target, CI mode checks every built-in release. Use `--target` or
`--glibc` to select the policy for a release pipeline. `--json` emits schema version
1; analysis errors go to stderr.

## Library

The Rust API provides `analyze(path)` for files and `analyze_bytes(label, bytes)` for
in-memory data. Compatibility evaluation and text/JSON rendering are separate APIs.

## Development

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo build --release --locked
```

Tests read committed fixture bytes; they never execute the fixtures. See
[`tests/fixtures/README.md`](tests/fixtures/README.md) for fixture provenance and
[`fuzz/README.md`](fuzz/README.md) for the optional fuzzing workflow.

## License

Project source is dual licensed under MIT or Apache-2.0; see
[LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE). Some prebuilt
fixtures include glibc, musl or compiler runtime code. Their notices are in
[`tests/fixtures/licenses`](tests/fixtures/licenses); retain them when redistributing
those fixtures.
