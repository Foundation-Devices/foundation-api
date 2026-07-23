# Foundation API

This monorepo contains the core crates for Foundation device-to-device protocols.

## Crates

-   **btp**: Beefcake Transfer Protocol for splitting messages into MTU sized chunks
-   **backup-shard**: Magic backup shard encoding
-   **ql-wire**: QuantumLink wire-format definitions
-   **ql-fsm**: QuantumLink Sans-IO protocol finite state machine
-   **ql-runtime**: QuantumLink async runtime
-   **ql-rpc**: RPC modality layer over QuantumLink streams

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
