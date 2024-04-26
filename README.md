# MTU Finder

MTU Finder is a utility tool written in Rust that helps determine the optimal Maximum Transmission Unit (MTU) for a network connection between your machine and a specified destination IP address. It systematically tests different MTU sizes to find the largest size that does not fragment IP packets.

## Features

- Determines the optimal MTU size to avoid IP fragmentation.
- Command-line interface for easy integration and automation.
- Uses progressive scanning from a specified range to find the best MTU.

## Getting Started

### Prerequisites

Ensure you have Rust and Cargo installed on your system. You can download them from [rust-lang.org](https://www.rust-lang.org/tools/install).

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

The executable will be located in `./target/release/`.

### Usage

Run the tool from the command line, specifying the destination IP address and optionally the range of MTU sizes to test.

```bash
./target/release/mtu_finder -d 192.168.1.1 -r 1300:1500
```

**Parameters:**
- `-d, --destination`: Destination IP address to test the MTU size.
- `-r, --range`: Range of MTU values to test (format: min:max), defaults to `1300:1500`.

### Example

```bash
./target/release/mtu_finder -d 192.168.1.1 -r 1400:1450
```

This will test MTU sizes from 1400 to 1450 to find the optimal MTU for the network connection to `192.168.1.1`.

## License

This project is licensed under the GNU General Public License v3.0 - see the [gpl-3.0.md](gpl-3.0.md) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request or open an issue for any bugs found or improvements you suggest.
