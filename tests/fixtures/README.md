# Fixture provenance

These are committed ELF files, read as data, never executed or dynamically loaded.
All start from the tiny sources in `src/`, built with `generate.sh`. Fixtures have
0644 permissions. `manifest.json` records their SHA-256 hashes and sizes.

| Fixtures | Construction |
| --- | --- |
| pie, non-pie, shared-library, static-glibc, static-pie | `tiny.c`, native GCC/glibc; static variants include libc code |
| musl-dynamic, musl-static | `tiny.c`, real musl-gcc; static variant includes musl |
| glibc-old, glibc-new | No system CRT/libc; link to controlled libc ABI stubs with GNU version scripts |
| glibc-old-shared | Shared library linked to controlled stubs, with a mandatory GLIBC_2.17 floor |
| abi-version-invalid, abi-version-gnu | Copies of glibc-old-shared with System V ABI version 255 or GNU ABI version 1 |
| weak-version, weak-symbol-hard-version | Same weak symbol import; GLIBC_2.39 version record flags deliberately set or cleared independently of symbol binding |
| repeated-auxiliary | Shared library linked with two DT_AUXILIARY entries |
| padded-interpreter | glibc-old with PT_INTERP extended over one additional NUL byte |
| aarch64-glibc-new | Cross-compiled by clang/lld with AArch64 glibc namespace baselines; not executed |
| i386-glibc-new, elf32 | GCC ELF32, no installed 32-bit libc needed |
| namespaces | Controlled GLIBCXX, CXXABI, GCC, OPENSSL and unrelated GLIBC namespaces |
| versioned-provider | Version definitions only; verifies that exports are not requirements |
| copy-relocation | Non-PIE data import with a copy relocation and required symbol version |
| rpath, runpath | Literal loader search-path metadata, including an empty component |
| x86-64-v2/v3/v4, isa-used-only, isa-unknown-bits | Assembly emits controlled GNU properties; the bodies do not establish instruction-level coverage |
| vendor-note | Declared x86-64-v3 GNU property plus a separate vendor note with four-byte framing and section alignment 1 |
| aarch64-big-endian, relocatable | Cross/native compiler objects for metadata coverage |
| sectionless | glibc-new with section-header references removed; valid segment metadata, intentionally incomplete v0.1 version analysis |
| hidden-version-index | glibc-new with the version-index flag bit set |
| bad-version-index, bad-verneed, malformed-elf, truncated-elf, non-elf | Deliberate corruption/non-ELF inputs |

The controlled provider named `libc.so.6` is only a linker stub. It is not a libc
implementation. Fixture symbol versions test causality without requiring the build
host to have glibc 2.39. In particular, these files do not prove any hardware or
distribution execution result. A plain decoy `GLIBC_99.99` string and GLIBC requirements
from an unrelated library verify that string scanning is insufficient.

Rebuild on Linux with Bash, Rust/Cargo, GNU coreutils (including `sha256sum`), GCC,
GNU ld, musl-gcc, clang and lld:

```sh
bash tests/fixtures/generate.sh
cargo test --locked
```

The Bash script compiles the sources, then runs the Rust `fixture-tools` example
to mutate controlled fixture bytes and write the manifest. Hashing passes bytes to
`sha256sum` over stdin. Neither tool executes the results or calls ELF inspection
utilities. An optional output-directory argument permits an isolated rebuild:

```sh
bash tests/fixtures/generate.sh /tmp/binport-fixtures-rebuilt
```

Compiler-linked fixtures can change with compiler/libc updates; review the resulting hashes and
metadata. Tests assert native fixture structure rather than host-specific glibc floors.
All explicit version-floor fixtures use controlled stubs.

The sources and generator are covered by the project MIT license. Native libc/CRT
fixtures also contain third-party code. Corresponding notices are in `licenses/`.
The glibc and musl projects permit relinking/rebuilding these fixtures from the supplied
tiny sources; the exact commands are in the generator. Preserve third-party notices
when redistributing prebuilt fixtures.
