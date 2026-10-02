# Using crowsi-certificate-manager

Manage certificate issue, renewal, revocation and reconciliation through explicit lifecycle inputs.

## Before you start

Certificate authorities, keys and deployment trust must be supplied through the configured boundaries. Lifecycle state is not proof of public TLS readiness.

## First steps

Run from the repository root:

```sh
cargo test --locked
```

## How to assess the result

- Inspect certificate status and renewal requirements.
- Track lifecycle changes in configured local state.

A passing source-level check establishes only what that check observes. Keep missing configuration, unavailable services and unverified deployment paths visible.

## Continue reading

[Repository overview](../README.md)
