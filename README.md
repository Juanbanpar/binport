# binport

Explain the declared Linux ABI requirements of a release artifact, without running it.
binport connects imported symbols to their version indices, version requirements,
and providing libraries. When a glibc baseline is too old, it reports the exact
symbols responsible.

```sh
cargo install --path . --locked
binport ./myprogram
binport inspect ./myprogram
binport ./myprogram --json
binport ./myprogram --target debian-12
binport ./myprogram --target ubuntu-22.04 --fail-incompatible
binport ./myprogram --glibc 2.31 --fail-incompatible
```

`--glibc-max` is an alias for `--glibc`. Repeat `--target` to check several releases.
Without a target or explicit glibc policy, binport reports all built-in releases.
An explicit glibc policy checks only the glibc ceiling, unless distribution targets
are also supplied. RPATH/RUNPATH entries, including `$ORIGIN` and empty components,
are reported literally, never expanded or resolved.

For example, the included `glibc-new` fixture produces these findings:

```text
Runtime
  Interpreter: /lib64/ld-linux-x86-64.so.2
  libc: Glibc
  glibc >= 2.39

glibc requirement
  GLIBC_2.39
  Introduced by:
    pidfd_spawn@GLIBC_2.39
    pidfd_spawnp@GLIBC_2.39
```

Its Debian 12 glibc check fails with `available glibc 2.36 < required 2.39`,
and its Debian 13 declared ABI checks pass. This is a controlled linker fixture,
not an application execution test.

## What compatible means

The distribution verdict covers the supported architecture and ELF ABI, loader family
and standard interpreter path, numeric glibc floor, and declared x86 ISA constraints
when target CPU information is available. It checks the distribution's edition
matching the artifact's architecture, never the developer machine's architecture.

`compatible` means those declared ABI checks pass. It is **not a guarantee that the
program will run**: arbitrary dependencies, transitive dependencies, C++/OpenSSL
runtimes, kernel requirements, deployment configuration, and undeclared CPU
instructions are outside this release's checks. The text report states this scope;
JSON consumers must apply the same interpretation.

Every constraint has its own `compatible`, `incompatible`, or `unknown` result,
a reason, and a `required` flag. Any incompatibility determines the overall result.
Otherwise, a required unknown determines an unknown result.

The ELF ABI version is retained separately from the OS ABI. A System V shared
library with a nonzero ABI version is incompatible with the glibc loader profile.
Other nonzero ABI versions produce `unknown`; binport does not infer support for
GNU ABI extensions from a distribution's glibc version.

Weak version requirements (`VER_FLG_WEAK`) remain visible but do not raise the
mandatory glibc floor. If a target cannot establish one, the glibc check is `unknown`:
binport does not evaluate symbol-binding or fallback behavior. A weak symbol alone
does not make its version requirement optional; the version record's flag controls
this distinction. An unmet mandatory requirement still produces `incompatible`.

Missing GNU CPU metadata is an explicit, informational unknown in the default ABI
check, as CPU inference is out of scope. It does **not** imply x86-64-v1 compatibility.
To make CPU compatibility a required check, declare the target machine's ISA:

```sh
binport ./myprogram --target debian-12 --cpu x86-64-v2 --fail-incompatible
```

With `--cpu`, an undeclared binary ISA produces `unknown`; a declared v3 requirement
against a v2 target produces `incompatible`. A declared v2/v3/v4 requirement without
`--cpu` also produces `unknown`: a distribution release does not tell us which CPU
the target machine has. `GNU_PROPERTY_X86_ISA_1_USED` is not treated as a requirement;
only `GNU_PROPERTY_X86_ISA_1_NEEDED` establishes one. Unknown requirement bits remain
unknown. AArch64 metadata and symbol versions are supported, but its CPU features
are not inferred.

## CI exit codes

Inspection mode returns 0 when analysis succeeds, even if some targets fail.
Use `--fail-incompatible` to enforce the selected checks:

| Code | Meaning |
| --- | --- |
| 0 | All selected checks are compatible within the documented scope |
| 1 | At least one target or explicit constraint is incompatible |
| 2 | Analysis, file I/O, target selection, or argument error |
| 3 | No incompatibility found, but a required check is unknown |

Without a target, CI mode enforces **every** built-in release. Prefer an explicit
`--target` or `--glibc` for release pipelines. Analysis and selection errors with
`--json` produce a JSON error on stderr and no stdout; clap argument errors use
standard CLI diagnostics on stderr. Help/version return 0.

## Supported analysis and boundaries

- ELF32 and ELF64, both endiannesses, using `elf` 0.8. Deep deployment profiles are
  x86_64 and AArch64, 64-bit little-endian. Other machines/ABIs are reported with an
  unknown architecture check; they are not silently assumed to be supported.
- Executables, PIE, shared libraries, relocatable objects and core file metadata.
  ET_DYN with PT_INTERP or DF_1_PIE is an executable. This also identifies static PIE.
  Relocatable/core/other objects are not given a positive deployment verdict.
- PT_INTERP; static/dynamic linking; DT_NEEDED, DT_SONAME, DT_RPATH and DT_RUNPATH.
  Padded interpreter strings and repeatable dynamic tags such as DT_AUXILIARY are
  accepted; auxiliary libraries are not resolved.
- `.dynsym` → `.gnu.version` → `.gnu.version_r`, with masked version-index flag bits,
  copy-relocation imports, provider names, weak-version flags, and all version
  namespaces preserved.
  Exported version definitions do not raise the required glibc floor.
- Numeric glibc ordering (`2.9 < 2.10`, including patch components) from recognized
  glibc providers, not strings that happen to contain `GLIBC_`. Non-numeric glibc
  requirements such as `GLIBC_PRIVATE` and `GLIBC_ABI_DT_RELR` yield an unknown check.
  Only mandatory version records contribute to the numeric floor.
- libc classification uses interpreter, dependencies and version-provider signals.
  Missing `GLIBC_*` is not evidence of musl. Static artifacts have unknown embedded
  libc and no dynamic glibc floor; this does not establish their kernel requirements.
- Standard stripped binaries retaining dynamic sections work. **Section-header-free
  binaries have dynamic dependencies/interpreters reported, but symbol-version
  analysis is incomplete and compatibility remains unknown.** v0.1 does not reconstruct
  dynsym/version tables from dynamic addresses and hash tables alone.
- Malformed metadata is rejected with errors. The parser validates table bounds,
  version chains, symbol/version counts and GNU note framing; it never executes or
  dynamically loads the artifact. Non-UTF-8 metadata strings produce analysis errors.

There are no calls to `ldd`, `readelf`, `objdump`, `file`, or `strings`; no subprocesses
in the analysis library; no host-runtime probing, dependency downloading, disassembly,
network database queries, or async runtime. The tool does not resolve arbitrary SONAMEs.
RPATH/RUNPATH can alter the actual loaded runtime, which cannot be verified here.

Rootfs inspection (`--root`), dependency resolution, kernel floors, other executable
formats, and automatic fixes are deferred. `--root` is intentionally not accepted.

## Library

```rust
use binport::{analyze, compat};

fn main() -> Result<(), Box<dyn std::error::Error>> {
let binary = analyze("tests/fixtures/glibc-new")?;
let releases = compat::distro::built_in()?;
let debian = releases.iter().find(|r| r.id == "debian-12").unwrap();
let result = compat::evaluate(&binary, debian, None);
assert_eq!(result.status, binport::Compatibility::Incompatible);
Ok(())
}
```

`analyze_bytes(label, bytes)` supports callers that already own artifact bytes.
The label is never opened. Analysis, compatibility and rendering are separate:

```text
ELF bytes → elf adapter → BinaryReport → compatibility evaluator
                                      → text / JSON renderer
```

`main.rs` delegates to CLI argument handling. Neither compatibility nor rendering
depends on parser types. `BinaryReport` and compatibility results are serializable
model types; future format adapters can populate the same model.

## JSON contract

Successful JSON has `schema_version: 1`, `binary: BinaryReport`, and
`compatibility: CompatibilityReport[]`. Enums use stable snake_case strings (the
`other` architecture carries its numeric `e_machine`); versions serialize as numeric
dotted strings; absent measurements are `null`, not zero. Binary metadata includes
numeric `os_abi` and `abi_version` fields. Requirement records contain `library`,
`version`, sorted, deduplicated `symbols`, and a boolean `weak` flag. Records with
different weak flags remain separate. The mandatory glibc summary contains
`minimum` and `causing_symbols` without version suffixes. Incompatibility causes in
constraint results include the suffix, such as `pidfd_spawnp@GLIBC_2.39`.

`version_requirements_complete: false` prevents an incomplete parse from becoming a
positive glibc check. Consumers should tolerate added fields in schema 1; incompatible
field/type/meaning changes require a new schema version. All unknown constraints
remain present in JSON even when the overall scoped verdict is compatible.

## Distribution data

[data/distros.toml](data/distros.toml) is embedded at compile time. Each baseline has
a source URL and verification date. It covers Ubuntu 20.04/22.04/24.04, Debian 12/13,
and RHEL 9. Updating it is a reviewable data change; it is not a package inventory or
a statement about the current patch level of a particular installed machine.

## Development

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo build --release --locked
```

Tests consume committed fixture bytes, so testing needs neither a C compiler nor
the tested architectures' runtimes. They test metadata, exact ABI causes, version
ordering, CPU declaration semantics, all exit codes, malformed input, every truncated
prefix of a versioned ELF, and deterministic byte mutations. CLI tests run with an
empty PATH. None of the fixture executables is run.

To rebuild fixtures deliberately, see [tests/fixtures/README.md](tests/fixtures/README.md).
There is no test-time fixture build, no network download and no host-binary dependency.

Full text/JSON CLI contracts are checked against reviewed files in
[tests/golden](tests/golden/README.md), including symbol causes, weak requirements,
all exit codes and stdout/stderr placement. Intentional updates require an explicit
environment variable; ordinary tests never rewrite expected output.

[fuzz/README.md](fuzz/README.md) describes the separate cargo-fuzz harness, verified
fixture seeding, resource limits and failure replay. CI runs a bounded fuzz smoke
test in addition to the deterministic suite. Fuzzing dependencies do not enter
the application package.

Project source is MIT licensed. Prebuilt fixtures linked with glibc, musl and compiler
runtime code include third-party code; see the fixture license notices.
