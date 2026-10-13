# Contributing

- `cargo test-all` runs everything in-process (never `--all-features`, see AGENTS.md); see [AGENTS.md](AGENTS.md)
  for the commands and conventions, and the README for what the library does.
- Every change touching verification, push handling or de-duplication adds the negative test (the
  SET that must be rejected) before the positive one.
- CI (`.github/workflows/ci.yml`) runs formatting, clippy with warnings as errors, the tests, the
  documentation build, the minimum Rust version, the store tests on PostgreSQL and MySQL, and a
  comparison of the SQL files with the Java repository.
- Releases follow the version of the Java library; the crates are published together from
  `release.yml` (to come) with crates.io trusted publishing.
