# Repository Guidelines

## Project Structure & Module Organization
- `src/`: core library code. Protocol modules live in `src/nfs3.rs`, `src/nfs4.rs`, `src/pnfs.rs`, RPC/XDR helpers in `src/rpc.rs` and `src/xdr.rs`, high-level clients in `src/client.rs` and `src/client41.rs`.
- `tests/`: integration-style tests using `nfsserve` (e.g., `tests/nfs3_nfsserve.rs`) and optional VM-based tests (`tests/nfs41_vm.rs`).
- `examples/`: small CLI examples (`nfs_ls`, `nfs_cat`, `nfs4_cat`).
- `docs/` and `scripts/`: documentation and VM harness scripts for NFSv4.1 testing.

## Build, Test, and Development Commands
- `cargo build`: compile the library.
- `cargo test`: run unit/integration tests (NFSv3 uses in-process `nfsserve`).
- `cargo test --test nfs3_nfsserve`: run the NFSv3 integration tests.
- `cargo test --test nfs41_vm -- --ignored`: run NFSv4.1 VM tests (requires the VM harness).
- `cargo fmt`: format code; keep local formatting aligned with CI.
- `cargo clippy --all-targets -- -D warnings`: lint with warnings as errors.
- `cargo run --example nfs_ls -- <server> <export> <path>`: sample NFSv3 list.

## Coding Style & Naming Conventions
- Language: Rust 2024 edition.
- Formatting: standard `rustfmt` defaults.
- Naming: `snake_case` for functions/vars, `CamelCase` for types, `SCREAMING_SNAKE_CASE` for constants.
- Keep APIs consistent with existing `Result<Result<T, NfsError>>` patterns in NFS clients.

## Testing Guidelines
- Use `tokio::test` for async integration tests in `tests/`.
- Prefer hermetic tests (e.g., `nfsserve`) for NFSv3. VM-based tests should be `#[ignore]`.
- Name tests with clear intent, e.g. `nfs3_write_roundtrip_using_nfsserve`.

## Commit & Pull Request Guidelines
- Commits follow Conventional Commits: `type(scope): summary` (e.g., `feat(nfs3): add readdir helpers`).
- PRs should include: purpose, key changes, test results (`cargo test` / `cargo clippy`), and any required setup steps.
- Link related issues when applicable; include logs or screenshots only if UI/CLI output is relevant.

## Notes on Compatibility
- Current transport is ONC RPC over TCP; authentication uses `AUTH_SYS`.
- NFSv4.1 and pNFS rely on Linux server behavior; validate against real servers when changing protocol logic.
