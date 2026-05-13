# MicroSync

A tiny, zero-bloat, open-source P2P widget engine built in Rust.

## Features
- **Ultra-Lean**: Optimized for minimum binary size and memory footprint.
- **P2P Architecture**: Decentralized state synchronization using `tokio` and `bincode`.
- **High-Performance GUI**: Built with `egui` (immediate mode) for 0% idle CPU usage.
- **Privacy First**: No centralized servers for data; direct peer-to-peer communication.

## Tech Stack
- **Language**: Rust
- **GUI**: [egui](https://github.com/emilk/egui)
- **Async Runtime**: [tokio](https://tokio.rs/)
- **Serialization**: [bincode](https://github.com/bincode-org/bincode)
- **Networking**: Raw TCP/UDP (WIP)

## Building
To build for production with size optimizations:
```bash
cargo build --release
```

## License
MIT
