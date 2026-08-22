# MTU Finder

MTU Finder is a utility tool written in Rust that determines the optimal Maximum Transmission Unit (MTU) for the network path between your machine and a destination IPv4 address. It sends do-not-fragment ICMP echo requests of increasing sizes and finds the largest one that is answered.

## How it works

1. **Preflight** — the *smallest* size in the range is probed first. If even that fails, the tool exits with an error instead of reporting an unverified number.
2. **Binary search** — the "size S is answered" predicate is monotonic, so the search converges in ~`log2(range)` probes (a few seconds, not minutes).
3. **Typed outcomes** — every probe is classified as:
   - `Fits` — a matching echo reply was received;
   - `TooLarge` — the kernel definitively refused to send (packet exceeds the interface MTU with DF set);
   - `Inconclusive` — no reply after retries. A timeout is **not** proof of "too large" (it can also mean filtered ICMP, loss, or a silently dropped oversized packet), so the tool treats it conservatively and flags the result.
   - `Fatal` — backend error unrelated to packet size.
4. **Boundary confirmation** — the reported MTU is re-probed before being printed.

Notes on the result:

- The reported value is the **largest size verified to be answered**. When the boundary was inferred from timeouts, the output says so explicitly.
- When the result equals the top of the tested range, the true MTU may be higher — widen `-r` to keep going.
- Do-not-fragment is set per platform: `IP_MTU_DISCOVER=IP_PMTUDISC_DO` on Linux, `IP_DONTFRAG` on macOS and FreeBSD, and via the Windows ICMP API on Windows.

## Platform support

| Platform | Backend | Notes |
|---|---|---|
| Linux, macOS, FreeBSD | native `SOCK_DGRAM/ICMP` socket | no root required |
| Windows | [`ping-rs`](https://crates.io/crates/ping-rs) | the Unix path of `ping-rs` rejects large payloads and ignores DF, so it is only used on Windows |

## Getting Started

### Prerequisites

Ensure you have Rust and Cargo installed. You can download it from [rust-lang.org](https://www.rust-lang.org/downloads).

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/stefb69/mtu-finder.git
   ```
2. Change into the project directory:
   ```bash
   cd mtu-finder
   ```
3. Build the project:
   ```bash
   cargo build --release
   ```

The executable will be located at `./target/release/mtu-finder`.

### Usage

```bash
./target/release/mtu-finder -d 192.168.1.1 -r 1300:1500
```

**Parameters:**
- `-d, --destination <IP>`: Destination IPv4 address to probe (required).
- `-r, --range <MIN:MAX>`: Range of MTU values to test (inclusive), defaults to `1300:1500`. The minimum must be at least 28 (20-byte IPv4 header + 8-byte ICMP header) and not greater than the maximum.

### Example

```bash
./target/release/mtu-finder -d 8.8.8.8 -r 1400:1500
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | A working MTU was found and reported. |
| `1` | Runtime error (unreachable destination, ICMP filtered, backend failure). |
| `2` | Invalid command-line arguments. |

## Testing

Unit tests are deterministic (they run the search against a fake ICMP backend with a configurable MTU threshold, plus checksum and argument-parsing tests):

```bash
cargo test
```

A real-network smoke test against `8.8.8.8` is marked `#[ignore]` and can be run explicitly:

```bash
cargo test -- --ignored
```

## License

This project is licensed under the GNU General Public License v3.0 - see the [gpl-3.0.md](gpl-3.0.md) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request or open an issue about any bugs found or improvements suggested.
