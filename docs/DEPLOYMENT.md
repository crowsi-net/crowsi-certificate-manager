# Deployment requirements

The library is intentionally unavailable until every production port is
composed. Tests use memory doubles; those are not deployment examples.

## Local adapter

Run the manager and CA adapter as separate least-privilege OS identities. Use
absolute Unix socket paths under owner-only `0700` directories and owner-only
socket permissions. The listener must bind peer credentials, executable
attestation, dispatch evidence, and proof-key evidence to the accepted stream
before creating `WorkloadEvidenceV2`.

Coela submits only an opaque intent or dispatch handle to the service-owned
orchestration endpoint. The service adapter obtains PA authorization and
custody locally, calls the manager, retains the full response, and exposes only
a redacted operation-status projection. Coela receives no credentials,
certificate bytes, receipts, or direct database/CA access. Do not introduce a
Coela-only privileged endpoint.

The IPC/authentication adapter must re-derive current workload and device
identity on every call and resume. The custody adapter must return a current,
non-exportable-key attestation for issue/renew and reject custody input for
revoke/status. Adapter results are snapshotted before PA acceptance and must be
safe for pure validation after durable acceptance; no untrusted field may be
reintroduced during that final check.

## Storage

The operation-state adapter needs an owner-only durable database with:

- atomic replay reservation, lifecycle CAS/fence, audit and outbox;
- atomic handoff-pending and handoff-accepted/pending-invocation substates;
- exact operation-row revision compare-and-swap on every transition;
- durable `invoked_at` readback before crossing the CA boundary;
- append-only invocation and reconciliation evidence;
- trusted-clock watermark and overflow rejection;
- startup migration/DDL attestation and no memory fallback.

The PA adapter must journal and replay the exact signed acceptance receipt and
ACK without issuing a new nonce or operation. It must distinguish
pre-acceptance signed `NotAccepted` from post-acceptance recovery. A durable
accepted row cannot use a generic abandon API. Deploy a separately authorized,
signed, journal-backed non-execution resolution/reconciliation procedure for
accepted operations that can no longer be invoked.

An independent integrity-alert sink must use separate storage and credentials.
Do not implement it as another table or transaction in the operation database.

## Cryptography

Pin distinct identities, versions, SPKI digests, algorithms and purposes for
CA signing, CA receipt signing, readiness attestation, PA verification,
custody attestation, manager-commit receipt signing, and manager-handoff
receipt signing. In particular, CA signing, CA outcome evidence,
manager-handoff evidence, and manager-commit evidence are four independent key
uses and must never share material.
Reconciliation verifies both the original execution era and the current
receipt/attestation era, including role-swap rejection.

CA receipt and manager-commit evidence remain 64-byte canonical P1363 low-S
signatures. Only the certificate assembly adapter converts a verified CA
provider signature from P1363 to canonical X.509 DER. Test gates must reject
DER at the provider/evidence boundary, non-canonical or high-S signatures,
wrong algorithms, and key ID/version/SPKI/purpose substitutions.

Pin the provider target normalizer ID and opaque version in both PA policy and
manager configuration. The adapter proves normalization before PA
authorization and passes only the canonical resource ID into commands, status
queries, lifecycle storage, and fence keys.

The authority adapter must provide an idempotent command journal keyed by the
canonical authority-command digest. Its reconciliation receipt is signed only
after journal lookup and reports `not-executed`, `completed`, or
`still-unknown`. The manager independently parses and verifies returned X.509
DER, trust chain, profile, fingerprint and receipt. The adapter receives the
durable `invoked_at`, executes the command at most once, and signs its actual
`executed_at`. That time must be at or after `invoked_at` and before the
original authority-readiness and applicable custody deadlines.

The trusted-clock adapter must support the two handoff barriers: one after all
external verifiers complete but before PA acceptance, and one after the exact
PA ACK is durably recorded. It must reject rollback. Recovery policy may waive
only PA authorization expiry within `max_handoff_recovery_seconds`; it must
never waive the original authority-readiness or custody deadlines.

## Operational gates

Before enabling a service:

1. attest IPC ownership and executable identity;
2. attest state schema, permissions, backups and recovery;
3. attest independent alert delivery;
4. enroll non-exportable leaf and CA keys;
5. pin PA, CA receipt and attestation trust roots;
6. pin and attest the provider resource normalizer and alias test vectors;
7. pass crash/restart, replay, rollback, reconciliation and ACK-loss tests;
8. verify Coela sees only the redacted projection;
9. attest the manager-commit signer and dual-evidence outbox delivery;
10. prove `still-unknown` cannot release the original PA authorization;
11. prove handoff ACK loss retries exact evidence and calls no CA beforehand;
12. prove delayed completion signing remains inside its signed recovery window;
13. prove PA completion ACK loss leaves the delivery outbox recoverable;
14. prove PA handoff ACK recovery works after the original lease expires;
15. prove accepted handoff state cannot be abandoned after restart or trust failure;
16. prove current workload/device and issue-or-renew custody are reverified on resume;
17. prove revoke and status reject custody input;
18. prove the post-ACK trusted-time barrier prevents late CA invocation;
19. prove CA `executed_at` is bounded by durable invocation and original deadlines;
20. prove stale, skipped, repeated, and overflowing operation revisions fail closed.
