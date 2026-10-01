# Security boundary

## Authority and custody

The service leaf private key is created and retained by a device-local,
non-exportable custody provider. The manager accepts only a CSR or public SPKI
and proof of possession. The certificate authority signing key is held by a
separate Crowsi authority/HSM adapter.

Seven roles require distinct keys, SPKI material, versions, and independently
verified purposes:

1. certificate signing;
2. authority outcome/reconciliation receipt signing;
3. authority readiness attestation;
4. PA execution authorization;
5. leaf-key custody attestation;
6. certificate-manager durable-commit receipt signing;
7. certificate-manager PA-handoff receipt signing.

Role equality, including a cross-era swap of old signing and current receipt
keys during reconciliation, fails closed.

CA and manager evidence signatures use the key provider's exact
`ecdsa-p256-sha256-p1363-low-s` profile. The CA adapter has one additional,
explicit conversion boundary for X.509 certificates: after verifying the
64-byte low-S P1363 provider result, it converts `(r, s)` to canonical DER
`ECDSA-Sig-Value` without changing the TBS digest, key version, or SPKI.
DER input at the provider boundary, high-S twins, wrong algorithms, and
cross-purpose keys are rejected.

## Authentication and authorization

Production access is private authenticated IPC. The adapter derives peer UID,
GID, executable digest, workload identity, channel binding, and proof-key
evidence from the same connection. A browser payload cannot assert them.
The manager re-verifies that current workload and device on every call and
resume. Issue and renew additionally require a current custody attestation
stably bound to the original non-exportable key, CSR/SPKI, service workload,
device, resource, and purpose. Revoke and status require custody to be absent.

Every API uses a dedicated PA action. Mutation, certificate status, operation
status, and reconciliation authorizations are not interchangeable. The signed
lease binds the complete canonical request, owner, resource version, identity
revocation snapshot, lifecycle transition, fence, deployment, policy ancestry,
requester and approver. Mutation and reconciliation require distinct requester
and approver subjects.

Privileged approval claims are accepted only after the PA verifier has
independently verified signed, one-use, phishing-resistant evidence bound to
the exact request, action, actor, device, and canonical target. Read-only
certificate and operation status claims must omit every approval field.
Flattened claims are not self-asserted service input.

The target is fenced only under its provider-scoped canonical ID. The
authorization binds a normalization proof digest and the manager pins the
normalizer ID and opaque version. Mixed-case, dot-segment, unproved, or
alternate-normalizer aliases fail closed.

The verifier performs repeatable cryptographic and current-revocation checks.
One-use consumption happens only in the atomic operation-state transaction, so
a verifier retry cannot partially consume authorization.

## Durable safety

The production state adapter must provide a single crash-safe transaction for
replay keys, lifecycle CAS/fence, state revision, append-only audit and outbox.
It must compare exact owner, request, resource, command digest, reservation,
version, lifecycle epoch and operation-row revision on every transition. The
handoff revision sequence is exact: staged, accepted, invoked, and finalized
cannot repeat, skip, race, or overflow a revision.

Reserved operations may be abandoned only before a durable PA `Accepted`
handoff exists. Accepted and invoked operations are never reaped as failed:
they remain locked until signed, journal-backed resolution proves
`not-executed` or `completed`. A production deployment therefore needs a
separate non-execution resolution/reconciliation path; a generic timeout,
administrator update, or local cleanup must not clear the lock. Trusted-time
rollback and integer overflow fail closed.

PA unlock is a dual-evidence transition. The signed authority outcome proves
the exact disposition; a distinct manager-commit key proves that the matching
state revision was durably committed. Both proofs bind domain, deployment,
trust revision, action, authorization/JTI, lease, operation, canonical
resource, fences, epochs, and the authority-evidence digest. A
`still-unknown` proof records progress but never unlocks the original.

PA release is separately two phase. `released-pending-accept` does not promote
the fence or lifecycle epoch. The manager persists the exact authorization and
operation claims before its dedicated handoff key signs them. Only a verified
`Accepted` receipt and exact PA ACK can reach `executing`; an unknown ACK stays
reserved. `NotAccepted` is valid only after expiry and proves that no CA call
was made.

The state adapter stages `handoff-pending` before PA contact and durably records
`handoff-accepted/pending-invocation` before CA contact. Resume lookup precedes
time-sensitive preflight and requires exact request, command, and lease
digests. The complete authority command is re-derived from the original command,
persisted reservation, and independently verified sources, then compared
exactly with the staged command.

Before PA acceptance, trusted time bounds a snapshot of the current
authenticated workload/device, current issue-or-renew custody, authorization,
and authority readiness. After the exact PA ACK and durable accepted CAS, the
manager reads trusted time again and purely revalidates that same snapshot
before recording invocation. Only PA authorization expiry may be tolerated
inside the bounded recovery window. Original authority-readiness and custody
deadlines remain hard limits; accepting a PA receipt never extends them.

Invocation is durably recorded before the CA boundary and the authority journal
must execute the canonical command at most once. Its signed outcome
`executed_at` must be at or after the durable `invoked_at` and before the
original authority-readiness and, for issue/renew, custody deadlines. The
manager verifies those bounds before finalization or receipt creation.

Manager-commit evidence binds both durable event time and later signing time.
Its short signature window and signed, policy-bounded recovery deadline are
distinct. Existing signing work is recovered before issuing any random
challenge, and the PA delivery row remains until its exact claim-digest ACK is
durably stored.

Projection corruption is reported through an independent integrity-alert sink.
The sink must use a distinct failure domain from the state database; if the
alert cannot be durably emitted, the manager returns `AuditUnavailable`.

## Exposure policy

Coela receives only an opaque intent/dispatch acknowledgement and redacted
operation metadata from a service-owned adapter. The adapter—not Coela—obtains
the PA lease and custody proof, calls the manager lifecycle interface, and
retains its full response. Coela adds aggregation, display, and authorized
internal operation linking, not an alternate privileged path. It never receives
a PA lease, CSR, certificate bytes, identity evidence, receipt payload, private
key, or authority key. Debug output redacts encoded security envelopes.

Do not place the manager on an external listener. The SPIFFE-shaped identifiers
are closed policy identifiers, not a SPIFFE Workload API implementation.

## Private vulnerability reporting

Report vulnerabilities through this repository's GitHub private vulnerability reporting form. Do not put credentials, personal or customer data, or production certificate material in public issues or pull requests.
