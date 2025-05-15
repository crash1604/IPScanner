# Rust IP Scanner

## Overview
Rust IP Scanner is a command-line tool that scans a range of IP addresses for open ports. It is designed for speed and efficiency, leveraging multithreading to perform scans concurrently.

## Features
- Scan a range of IP addresses for open ports.
- Specify custom ports to scan.
- Adjustable timeout for port scanning.
- Multithreaded scanning for improved performance.
- Save scan results in JSON format.

## Installation

1. Ensure you have [Rust](https://www.rust-lang.org/tools/install) installed on your system.
2. Clone this repository:
   ```bash
   git clone <repository-url>
   cd IPScanner
   ```
3. Build the project:
   ```bash
   cargo build --release
   ```
4. The compiled binary will be available in the `target/release` directory.

## Usage

Run the scanner with the following command:
```bash
./target/release/ipscanner <start_ip> <end_ip> [OPTIONS]
```

### Arguments
- `<start_ip>`: The starting IP address of the range to scan.
- `<end_ip>`: The ending IP address of the range to scan.

### Options
- `-p, --ports`: Comma-separated list of ports to scan (default: `80,443,22,3389`).
- `-t, --timeout`: Timeout in milliseconds for each port scan (default: `500`).
- `-n, --threads`: Number of threads to use for scanning (default: `100`).

### Example
Scan the range `192.168.1.1` to `192.168.1.10` for ports `80` and `443` with a timeout of `1000ms` using `50` threads:
```bash
./target/release/ipscanner 192.168.1.1 192.168.1.10 -p 80,443 -t 1000 -n 50
```

## Test Cases

Run the test suite to verify the functionality of the application:
```bash
cargo test
```

### Included Tests
- **IP Address Conversion**: Ensures correct conversion between IP strings and integers.
- **Port Parsing**: Verifies that port strings are correctly parsed into a list of integers.
- **Invalid IP Handling**: Tests the handling of invalid IP addresses.

## To-Do

### Performance Improvements
1. **Asynchronous Networking**: Replace `TcpStream` with an asynchronous library like `tokio` for better performance.
2. **Batch Processing**: Implement batch processing of IPs to reduce thread contention.

### New Features
1. **IPv6 Support**: Add support for scanning IPv6 addresses.
2. **Custom Output Formats**: Allow users to specify output formats (e.g., CSV, XML).
3. **Interactive Mode**: Add an interactive mode for easier configuration.
4. **Exclude IPs**: Add an option to exclude specific IPs or ranges from the scan.
5. **Progress Indicator**: Display a progress bar during the scan.
6. **Logging**: Add detailed logging for debugging and audit purposes.

## License
This project is licensed under the MIT License. See the `LICENSE` file for details.