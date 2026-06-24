# Repository Guidelines

## Project Structure & Module Organization

```
src/
├── api/            # Axum HTTP routes, middleware, error handling
├── approval/       # Dual-control approval workflow (等保三级 双人复核)
├── audit/          # Audit logging, SQLite store, SM3 hash chain
├── auth/           # Session management, TOTP 2FA, recovery codes
├── backup/         # Key & master seed export/import (灾难恢复)
├── config.rs       # TOML-based configuration, CLI args (clap)
├── crypto/         # SM2/SM3/SM4 engines, envelope encryption, secure memory
├── evidence/       # Compliance self-assessment report (合规证据包)
├── hsm/            # KekProvider trait, software/PKCS#11/SDF providers
├── key/            # Key manager, store, types, dependency index
├── lib.rs          # Crate root, re-exports, Error enum
├── main.rs         # Binary entry point, TLS setup, graceful shutdown
├── monitor/        # Intrusion detection, metrics, syslog audit
├── policy/         # RBAC, security labels, ABAC policy engine
├── store/          # SQLite migrations, repository helper
└── trust/          # Binary/config integrity verification (SM3)
deploy/             # systemd unit, host hardening guide
tests/              # Integration tests (if added)
```

Each module in `src/` mirrors a 等保三级 security requirement. Keep cross-module coupling low; prefer trait-based interfaces (e.g. `KekProvider`, `AuditStore`, `ApprovalStore`).

## Build, Test, and Development Commands

```bash
cargo check                    # Fast compile check during development
cargo test --lib               # Run all unit tests (currently 59)
cargo test --lib <test_name>   # Run a specific test (e.g. test_rotate_key)
cargo check --features monitoring  # Verify syslog + Prometheus build
cargo check --all-features     # Verify PKCS#11 + SDF feature gates
cargo build --release          # Optimized release build (LTO + panic=abort)
```

Tests live as `#[cfg(test)] mod tests` inside each source file (not in `tests/`). Run the full suite before committing.

## Coding Style & Naming Conventions

- **Format**: `cargo fmt` (no explicit config; use Rust defaults).
- **Lint**: `cargo clippy` — zero warnings target.
- **Rust idioms**: `Result<T, Error>` via `src/lib.rs`; prefer `thiserror` for error enums.
- **Naming**: snake_case for functions/variables, CamelCase for types, SCREAMING_SNAKE for constants. Module names are single-word.
- **National crypto**: SM2/SM3/SM4 via `libsm` crate. Avoid AES/RSA in new code unless interoperability requires it.
- **Feature gates**: Use `#[cfg(feature = "...")]` for optional dependencies (`pkcs11-hsm`, `sdf-hsm`, `monitoring`). Don't gate modules that only use std.

## Testing Guidelines

- **Framework**: `#[tokio::test]` for async tests, `#[test]` for sync. Both use `#[cfg(test)]`.
- **Coverage target**: Every `pub fn` in core modules (crypto, key, approval, policy, audit) should have at least one test.
- **Naming**: `test_<module>_<scenario>` — e.g. `test_envelope_encryption_roundtrip`, `test_dependency_blocks_destroy`.
- **Pattern**: Arrange → Act → Assert. Use memory SQLite (`sqlite::memory:`) for DB tests. Avoid shared state between tests.
- **Run**: `cargo test --lib` — must pass before any commit.

## Commit & Pull Request Guidelines

**Commit messages**: Read `git log --oneline` for local conventions. Prefix with the area changed:

```
crypto: fix SM2 sign public key derivation
approval: add consume_approved_for to prevent replay
tests: add 18 inline tests, total 59 passing
```

- Keep subject under 72 characters. Use body for rationale.
- Reference 等保三级 items by number when relevant (`#4 双人复核`, `#11 完整性保护`).

**Pull requests**: Title should mirror commit prefix style. Description must include:
- What changed (1–2 sentences)
- Why (which requirement or issue it addresses)
- Verification steps (e.g. `cargo test` output)

## Security & Configuration Tips

- **Master seed**: Auto-generated on first run; stored at `data/master.seed` by default. Guard this file — it controls all KEK derivation.
- **TLS/mTLS**: Configure in `config.toml` under `[server.tls]`. `client_ca_path` enables mTLS. Without TLS, the server falls back to plain HTTP — not recommended for production.
- **Feature flags**: `monitoring` enables syslog and Prometheus metrics. `pkcs11-hsm` / `sdf-hsm` require real hardware.
- **Hardening**: See `deploy/hardening.md` for seccomp, SELinux, core dump, and `mlock` setup.
