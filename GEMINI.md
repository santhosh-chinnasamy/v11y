# Gemini Context: v11y

## Project Overview
`v11y` is a Rust-based CLI and TUI application for scanning and triaging vulnerabilities in Node.js projects. It currently wraps `npm audit --json` and processes the output to present actionable risk assessments.

## Design Goals
- **Reduce Cognitive Load**: `v11y` is specifically designed to help users process massive vulnerability reports (e.g., legacy projects with 600+ vulns). The TUI emphasizes split-pane layouts, contextual focus, and top-level summary metrics to make triage manageable and actionable rather than overwhelming.

## Tech Stack
- **Language**: Rust (Edition 2024)
- **CLI Framework**: `clap`
- **TUI Framework**: `ratatui`
- **Serialization**: `serde`, `serde_json`
- **Error Handling**: Standard `Result`, `color-eyre` for reporting
- **Formatting**: `comfy-table`, `tui-markdown`

## Architecture & Modules
- `src/main.rs`: Entry point orchestration (argument parsing, fetching audit data, processing, and output routing).
- `src/audit.rs`: Execution of external package manager audit commands (e.g., `npm audit`).
- `src/model.rs`: Data structures representing external tool outputs and internal domain models.
- `src/risk.rs`: Core logic for risk building, filtering (severity, fixability, direct/transitive), and sorting.
- `src/cli.rs`: CLI argument definitions.
- `src/terminal.rs`: Standard terminal/CLI output functionality.
- `src/tui.rs`: Interactive Terminal User Interface implementation.

## Engineering Standards & Guidelines
1. **Idiomatic Rust**: Adhere strictly to idiomatic Rust patterns, utilizing standard cargo tools (`cargo fmt`, `cargo clippy`). 
2. **Error Handling**: Robustly handle errors, particularly when interacting with external processes (like running `npm`) or parsing external JSON. Propagate errors clearly using the established conventions.
3. **Type Safety & Warnings**: Do not suppress compiler warnings or bypass the type system. Always fix the underlying issues.
4. **Testing**: When implementing new features (e.g., adding support for `yarn`, `pnpm`, or `bun`), add corresponding tests and fixtures (similar to `tests/fixtures/npm-audit.json`).
5. **Modularity**: Keep new package manager integrations isolated (e.g., within or alongside `audit.rs`) and map their outputs to the common internal models (`model.rs`, `risk.rs`).
