# Fuzzing

The `cargo-fuzz` harness is separate from the application and normal test
dependencies. It parses arbitrary bytes, evaluates compatibility and renders reports;
it never executes or loads an input.

From the project root, install the tools, seed the corpus from verified fixtures and
run the bounded smoke test:

```sh
rustup toolchain install nightly --profile minimal --component rust-src
cargo install cargo-fuzz --version 0.13.2 --locked
cargo fetch --manifest-path fuzz/Cargo.toml --locked
cargo run --locked --example fixture-tools -- seed-corpus
CARGO_NET_OFFLINE=true cargo +nightly fuzz run analyze_bytes -- \
  -max_total_time=60 -timeout=5 -rss_limit_mb=512 -malloc_limit_mb=128 -max_len=1048576
```

Corpus seeding verifies `tests/fixtures/manifest.json` and copies only listed files.
It preserves new corpus entries and does not modify the fixtures. The smoke run
checks parser and renderer safety, compatibility invariants, and malformed metadata.
It is not proof that every ELF is valid or will run.

Failures are saved under `fuzz/artifacts/analyze_bytes`. Replay one with:

```sh
cargo +nightly fuzz run analyze_bytes fuzz/artifacts/analyze_bytes/<artifact> -- \
  -timeout=5 -rss_limit_mb=512 -malloc_limit_mb=128
```

Keep these limits when replaying timeout or memory failures. Minimize an input with
`cargo +nightly fuzz tmin analyze_bytes <artifact>`, then add a deterministic
regression test before fixing the issue. Fuzz corpus, artifacts and build output are
ignored by Git.
