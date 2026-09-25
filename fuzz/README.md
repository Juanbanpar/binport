# Static ELF fuzzing

This is a separate, unpublished cargo-fuzz package. The application and normal
tests acquire no fuzzing dependencies. The harness passes bytes to `analyze_bytes`,
evaluates compatibility and renders reports; it never executes or loads a fixture.

From the project root:

```sh
rustup toolchain install nightly --profile minimal --component rust-src
cargo install cargo-fuzz --version 0.13.2 --locked
cargo fetch --manifest-path fuzz/Cargo.toml --locked
cargo run --locked --example fixture-tools -- seed-corpus
CARGO_NET_OFFLINE=true cargo +nightly fuzz run analyze_bytes -- \
  -max_total_time=60 -timeout=5 -rss_limit_mb=512 -malloc_limit_mb=128 -max_len=1048576
```

The Rust development tool verifies hashes and sizes against `tests/fixtures/manifest.json`
and copies only listed fixtures into `fuzz/corpus/analyze_bytes`. This includes
ELF32/64, both endiannesses, version chains, weak requirements, GNU properties,
static/dynamic artifacts and malformed inputs. It preserves newly discovered
corpus entries and never writes into `tests/fixtures`. It uses the existing Rust
dependencies and GNU `sha256sum` to hash bytes passed over stdin. Seeding requires
no C compiler and never invokes the fixture generator.

The harness checks:

- Parsing and rendering must not panic or trigger AddressSanitizer failures.
- Incomplete version evidence and required unknown constraints cannot yield a pass.
- Explicit CPU checks cannot pass x86 artifacts without declared ISA requirements.
- A mandatory glibc floor above a ceiling must fail, with causes backed by
  mandatory version records.
- An intentionally invalid header size must be rejected.
- Removing version sections must not establish compatibility while the input
  still requests a dynamic glibc runtime.
- Text rendering must not emit terminal escape characters from input metadata.

Arbitrary mutations are not assumed invalid. These checks are partial oracles,
not proof that every accepted ELF is valid or that a compatible artifact runs.
The 60-second CI run is a smoke test. For longer local campaigns, increase
`-max_total_time` (for example to 3600) while retaining resource limits.

The maximum generated input is 1 MiB. The timeout is per input, the RSS limit is
512 MiB for the entire fuzzer process, and the allocation limit is 128 MiB per
allocation. These detect some excessive resource use, including use by report
generation, but do not establish tight allocation bounds or cover larger files.
See the [Rust Fuzz Book](https://rust-fuzz.github.io/book/cargo-fuzz/guide.html)
and [libFuzzer options](https://llvm.org/docs/LibFuzzer.html#options).

Failures are saved under `fuzz/artifacts/analyze_bytes`. Replay one with:

```sh
cargo +nightly fuzz run analyze_bytes fuzz/artifacts/analyze_bytes/crash-HASH -- \
  -timeout=5 -rss_limit_mb=512 -malloc_limit_mb=128
```

On CI failure, download the `fuzz-failures` workflow artifact to obtain these inputs.

Keep the resource limits when replaying timeout/OOM findings. Minimize with
`cargo +nightly fuzz tmin analyze_bytes <artifact>` where appropriate, then add a
small deterministic regression to the normal tests before fixing the issue.
Corpus, artifacts and build outputs are ignored; the harness, lockfile and Rust
development tool are versioned. Keep shared dependency versions aligned with the root
`Cargo.lock` when updating the fuzz lockfile.
