# Test fixtures

`tests/fixtures` contains ELF inputs read by tests as data; the files are never
executed or loaded. `manifest.json` records their SHA-256 hashes and sizes.

The set covers ELF32/64, both endiannesses, x86_64 and AArch64; executable, shared,
static and relocatable files; glibc and musl metadata; symbol versions and GNU ISA
properties; and malformed inputs. The controlled provider named `libc.so.6` is a
linker stub, not a libc implementation.

Rebuild on Linux with Bash, Rust/Cargo, GNU coreutils, GCC/GNU ld, musl-gcc, clang and
lld:

```sh
bash tests/fixtures/generate.sh [OUTPUT-DIR]
cargo test --locked
```

The generator uses `fixture-tools` to update metadata and the manifest. Compiler-
linked fixture bytes can vary by toolchain; review the hashes and metadata after a
rebuild. Some fixtures contain glibc, musl or compiler runtime code. Preserve the
notices in [`licenses/`](licenses/) when redistributing those files.
