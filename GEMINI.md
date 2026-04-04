# Gemini Context: v11y

## Project Overview
`v11y` is a modular Rust-based CLI and TUI application for scanning and triaging vulnerabilities in Node.js projects. It is architected to be extensible across different package managers (npm, yarn, pnpm, bun) and focused on delivering a low-cognitive-load triage experience.

## Design Goals
- **Reduce Cognitive Load**: Designed for triaging massive vulnerability reports (600+ vulns). The TUI emphasizes split-pane layouts, contextual "blast radius" metadata, and color-coded status indicators.
- **Provider Agnostic**: The core logic and UI should not care which tool produced the audit data. All audit reports are mapped to a unified internal domain model.
- **Clean Separation**: Physical separation between business logic (`v11y-core`) and presentation logic (`v11y`) via a Cargo workspace.

## Tech Stack
- **Language**: Rust (Edition 2024)
- **Frameworks**: `clap` (CLI), `ratatui` (TUI), `serde` (Serialization)
- **Diagnostics**: `color-eyre` for human-readable error reporting.

## Workspace Architecture
The project is organized as a Cargo Workspace to enforce strict architectural boundaries:

### `v11y-core` (Domain & Business Logic)
- `model.rs`: The **Source of Truth**. Contains the unified domain models (`PackageRisk`, `Severity`, `Advisory`, `Metrics`) used by the entire workspace.
- `risk.rs`: Pure functional logic for scoring, sorting, filtering, and calculating metrics.
- `provider/`: Contains the `AuditProvider` trait. 
  - New package managers are added by implementing this trait in a submodule (e.g., `provider/npm`). 
  - Provider-specific JSON models are kept **private** to their respective modules.

### `v11y` (Presentation Layer)
- `main.rs`: Orchestrates the flow: Provider -> Logic -> UI.
- `cli.rs`: Command-line argument parsing.
- `tui/`: Modular TUI implementation.
  - `app.rs`: State management (`App` struct).
  - `render.rs`: Stateless rendering logic.
- `terminal.rs`: Static CLI table output.

## Engineering Standards & Guidelines
1. **Trait-Based Extensions**: To add support for a new package manager (e.g., `yarn`), implement the `AuditProvider` trait in `v11y-core`. Do not modify the TUI or `main.rs` beyond the initial provider instantiation.
2. **Unified Model Integrity**: The `PackageRisk` struct in `v11y-core` is the contract. All providers must map their raw output to this model.
3. **Stateless UI**: Keep TUI rendering functions in `render.rs` stateless. They should only take `&App` or `&mut Frame` and draw based on existing state.
4. **Error Handling**: Use `color_eyre::Result` everywhere. Ensure system command failures (e.g., `npm` not found) are wrapped with helpful context via `.wrap_err()`.
5. **Testing Strategy**:
   - Business logic in `risk.rs` must have unit tests covering edge cases.
   - New providers must include tests that parse their specific JSON fixtures (stored in `v11y-core/tests/fixtures`).
   - TUI state transitions in `app.rs` should be tested where logic is complex.
6. **No Leaky Abstractions**: Never expose provider-specific types (like `NpmVulnerability`) outside of their respective `v11y-core/src/provider/` submodules.
