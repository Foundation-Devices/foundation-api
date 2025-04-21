# Foundation API

This monorepo contains the core crates for a device-to-device API using Blockchain Commons' GSTP

## Crates

-   **abstracted**: Abstractions of the BLE and SE chips
-   **api**: The API - contains predefined QL messages
-   **api-demo**: Tokio-based demo of device-to-device communication
-   **btp**: Beefcake Transfer Protocol for splitting messages into MTU sized chunks
-   **quantum-link-macros**: Macros to easily turn Rust Structs and Enums into valid QL messages

## Development

To build and run the crates in this repository, you will need to have Rust and Cargo installed.

### Building

To build all crates:

```bash
cargo build
```

To build a specific crate:

```bash
cargo build -p <crate_name>
```

### Testing

To run all tests:

```bash
cargo test
```

To run tests for a specific crate:

```bash
cargo test -p <crate_name>
```

## Contributing

Contributions are welcome! Please see the contributing guidelines for more information.

## License

This project is licensed under the GPLv3 License.
