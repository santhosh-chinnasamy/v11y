# v11y

CLI / TUI tool to scan for vulnerabilities in Node projects and triage them. The goal is to provide a simple and efficient way to identify and manage vulnerabilities in your projects.

It uses the `npm audit --json` or `yarn audit --json` command under the hood to perform the actual scanning.

> v11y - a numeronym for "vulnerability" (v + 11 letters + y). Similar to a11y, i18n, k8s, etc.

## Installation

You can download the latest pre-built binaries for your platform from the [GitHub Releases](https://github.com/santhosh-chinnasamy/v11y/releases) page.

### Homebrew

```bash
brew tap santhosh-chinnasamy/tap
brew install santhosh-chinnasamy/tap/v11y
```

### macOS & Linux

1. Download the `.tar.gz` archive for your architecture (e.g., `v11y-x86_64-apple-darwin.tar.gz` for Intel Macs or `v11y-aarch64-unknown-linux-gnu.tar.gz` for ARM Linux).
2. Extract the archive:
   ```bash
   tar -xzf v11y-<target>.tar.gz
   ```
3. Move the binary to a directory in your `PATH`:
   ```bash
   sudo mv v11y /usr/local/bin/
   ```

### Windows

1. Download the `.zip` archive for your architecture (e.g., `v11y-x86_64-pc-windows-msvc.zip`).
2. Extract the archive.
3. Move `v11y.exe` to a folder in your `PATH`.

### From Source (using Cargo)

If you have Rust installed, you can install `v11y` directly from source:

```bash
git clone https://github.com/santhosh-chinnasamy/v11y.git
cd v11y
cargo install --path v11y
```

## Usage

Run the following command in the root of your Node.js project (where `package-lock.json` or `yarn.lock` is located):

```bash
$ v11y
```

### CLI Options

```bash
$ v11y --help
Usage: v11y [OPTIONS]

Options:
      --only-direct           Show only vulnerabilities from direct dependencies
      --min-severity <MIN_SEVERITY>
                              Minimum severity level [default: low] [possible values: low, moderate, high, critical]
      --only-fixable          Show only vulnerabilities that have a fix available
      --cli                   Output the results in a table format to the terminal instead of the TUI
      --pm <PM>               Manually specify the package manager [possible values: npm, yarn]
  -h, --help                  Print help
  -V, --version               Print version
```

## Roadmap

- [x] Scan for vulnerabilities using `npm audit` and `yarn audit`
- [x] Display results in a high-fidelity TUI
- [x] Show detailed information about each vulnerability (CWE, CVSS, etc.)
- [x] Filter vulnerabilities by severity
- [ ] Export results to a file (e.g., JSON, CSV)
- [ ] Integrate with CI/CD pipelines
- [ ] Upgrade vulnerable dependencies by selecting them in the TUI

## Supports

- [x] npm
- [x] yarn
- [ ] pnpm
- [ ] bun
