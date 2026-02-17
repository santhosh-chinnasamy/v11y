# v11y

CLI / TUI tool to scan for vulnerabilities in Node projects and triage them. The goal is to provide a simple and efficient way to identify and manage vulnerabilities in your projects.

It uses the `npm audit --json` command under the hood to perform the actual scanning. More package managers and features will be added in the future.

## Usage

```bash
$ v11y # scans the current directory and displays the results in a TUI
```

## Build and Install

```bash
cargo build
cargo install --path .
```

## Roadmap

- [x] Scan for vulnerabilities using `npm audit`
- [x] Display results in a TUI
- [ ] Show detailed information about each vulnerability
- [ ] Filter vulnerabilities by severity
- [ ] Export results to a file (e.g., JSON, CSV)
- [ ] Integrate with CI/CD pipelines
- [ ] Upgrade vulnerable dependencies by selecting them in the TUI

## Supports

- [x] npm
- [ ] yarn
- [ ] pnpm
- [ ] bun
