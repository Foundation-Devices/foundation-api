# Foundation API

## Usage

If doing a `git pull`, make sure to run `cargo update` to update the dependencies.

- `cargo test`: Run the tests.
- `cargo run`: Run the demo.

## Updates

**2024-06-14**

- Added `abstracted` module to the crate.
    - Now contains traits for abstracted hardware types, with the goal of making it easier to use the crate with a testing/development environment and with real hardware.
        - `AbstractBluetoothChannel` is implemented by `demo::BluetoothChannel`.
            - All the methods formerly in `passport` and `envoy` required to send and receive `SecureRequest` and `SecureResponse` messages are now in `AbstractBluetoothChannel`.
            - As a result, `passport` and `envoy` are now much simpler.
        - `AbstractEnclave` is implemented by `demo::Enclave`.
            - Adapted conversion APIs like `SecureTryInto` to take an `AbstractEnclave` instead of a `&Enclave`.
    - I did not factor out the `Screen` and `Camera` types from `demo`, as they are likely to be very different in a real-world implementation.
- Reformatted codebase using `Prettier`.
