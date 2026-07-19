# Dustonic

Dustonic is a modern, privacy-first PC cleaner and optimizer for Windows and Linux.

## Development

```bash
npm install
npm run dev
```

## Releases

Download the latest release artifacts from:

<https://github.com/bytepassperks/dustonic/releases>

Windows releases include NSIS (`.exe`) and MSI installers. Linux releases include
AppImage, Debian (`.deb`), and RPM (`.rpm`) packages. Current installers are
unsigned; code signing is planned for a future release.

## Build from source

Build the frontend:

```bash
npm run build
```

Build the native application for the current operating system:

```bash
npx tauri build
```

For a local Linux binary without installer bundling:

```bash
cargo build --manifest-path src-tauri/Cargo.toml
```

Run checks:

```bash
npm run lint
npm run format
cargo fmt --manifest-path src-tauri/Cargo.toml --check
cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets --all-features -- -D warnings
cargo test --manifest-path src-tauri/Cargo.toml
cd website && npm install && npm test
```

Dustonic is proprietary commercial software. Use is subject to the Dustonic
Proprietary Software License and applicable purchase terms.
