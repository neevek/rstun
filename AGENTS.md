# Repository Guidelines

## Project Structure & Module Organization
- `src/` contains all Rust sources. Key modules: `src/client.rs`, `src/server.rs`, `src/tcp/`, `src/udp/`, `src/tunnel_*`.
- `src/bin/rstunc.rs` and `src/bin/rstund.rs` are the CLI entrypoints for client/server.
- `gen_cert_and_key.sh` is a helper for generating local certs. `localhost.*.pem` are test assets.
- `target/` is build output (do not commit changes there).

## Build, Test, and Development Commands
- `cargo build` — compile the workspace.
- `cargo run --bin rstund -- --help` — run the server CLI.
- `cargo run --bin rstunc -- --help` — run the client CLI.
- `cargo fmt` — format Rust code (if rustfmt is installed).
- `cargo clippy` — lint for common issues (if clippy is installed).

## Coding Style & Naming Conventions
- Follow standard Rust style: 4-space indentation, `snake_case` for functions/variables, `CamelCase` for types, `SCREAMING_SNAKE_CASE` for constants.
- Keep modules focused; colocate TCP/UDP logic in `src/tcp/` and `src/udp/`.
- Prefer clear, structured logging via `log` macros and propagate errors with `anyhow`.

## Testing Guidelines
- No automated tests are currently present in the repository.
- If you add or refactor behavior, consider adding tests under `src/` with `#[cfg(test)]` modules or a `tests/` directory.
- Run `cargo test` when tests are added.

## Commit & Pull Request Guidelines
- Recent commits use short, imperative summaries (e.g., “refactor …”, “fix …”). Follow that style.
- Keep commits scoped to one logical change when possible.
- If opening a PR, include a brief description of behavior changes and any relevant CLI examples.

## Security & Configuration Tips
- Use valid certificates in production; the bundled `localhost` certs are for local testing only.
- When adding config options, update `README.md` CLI help sections and examples.
