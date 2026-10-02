# crowsi-certificate-manager

Manage certificate issue, renewal, revocation and reconciliation through explicit lifecycle inputs.

## What you can do

- Inspect certificate status and renewal requirements.
- Track lifecycle changes in configured local state.

## Current scope

Certificate authorities, keys and deployment trust must be supplied through the configured boundaries. Lifecycle state is not proof of public TLS readiness.

Package distribution is not activated by this documentation. Use the checked-in source and the declared dependency versions; published availability must be verified separately.

## Getting started

Install Rust 1.97 or newer and make the declared dependencies available. Use the configured private registry when a dependency is not distributed publicly. Run from this repository:

```sh
cargo test --locked
```

## Documentation and source

[Interface reference](docs/interface-reference.md)

[Usage guide](docs/getting-started.md)

[Schemas](schemas) · [Detailed documentation](docs) · [Implementation and public interfaces](src) · [Verification cases](tests) · [Contributing](CONTRIBUTING.md) · [Security reporting](SECURITY.md) · [License](LICENSE) · [Attribution notices](NOTICE)
