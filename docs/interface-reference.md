# crowsi-certificate-manager interface reference

Use the [usage guide](getting-started.md) for the first steps. This reference preserves the current interface details and operational limits. Run command examples from the repository root, after preparing the exact declared dependencies and registered configuration.

## Service integration

Each service integrates through a private `native-ipc` adapter and supplies:

- a V2 management command;
- a signed, one-use PA/PEP execution authorization for the exact action;
- for issue or renew, a public CSR/SPKI proof plus a signed non-exportable-key
  custody attestation.

The adapter derives workload evidence from the accepted IPC stream. Peer UID,
executable identity, dispatch evidence, or workload claims are never accepted
from browser or service JSON. Public certificate bytes return only to that
authenticated service. Control-plane projections contain metadata and opaque
audit references only.

Every call and resume re-authenticates the current service workload and device
on the current IPC stream. Issue and renew also require a current
non-exportable-key custody attestation bound to the original CSR/SPKI and
workload. Revoke and status forbid custody input; they never cause a custody
attestation to be supplied merely to satisfy a generic interface.

Certificate lifecycle epochs and identity revocation epochs are independent.
Issue uses lifecycle `0 -> 0`, renew/status preserve the current lifecycle
epoch, and revoke advances it by exactly one. Mutation fencing advances once;
status is read-only; reconciliation consumes a fresh PA fence while preserving
the locked original lifecycle transition.

The PA verifier proves that `resource_id` is the provider-scoped canonical
identifier produced by the deployment-pinned normalizer ID and version. Its
normalization proof digest is retained in authorization ancestry. Services
normalize before requesting a fence; Coela cannot mint this proof or choose an
alternate resource alias.

Issue, renew, revoke, and unknown-result reconciliation require independently
signed, phishing-resistant user-presence evidence. Certificate and operation
status authorizations carry no approval fields. Receipts keep separate opaque
policy and operator-approval references; neither evidence payload is exposed
to Coela.

## Crash-safe execution

The durable state adapter atomically reserves request ID, nonce, authorization
ID, JTI, lease digest, lifecycle CAS/fence, audit intent, and outbox entry. Each
transition uses an exact operation-row revision CAS; a stale, skipped, repeated,
or overflowing revision fails closed. Before PA contact, the exact command is
staged as `handoff-pending`. The PA keeps the fence in
`released-pending-accept`; only an independently verified signed `Accepted`
receipt, its exact replay-safe PA ACK, and a durable
`handoff-accepted/pending-invocation` transition permit CA invocation.

Handoff validation has two trusted-time barriers. Immediately before PA
acceptance, the manager snapshots and verifies the current authenticated
workload/device, current issue-or-renew custody, PA authorization, authority
readiness, and the fully re-derived command. Immediately after the durable PA
ACK, it reads trusted time again and purely revalidates that same snapshot
before recording invocation. Bounded crash recovery may cross only the PA
authorization expiry; it may never cross the original authority-readiness or
key-custody deadline.

Once `Accepted` is durable, generic abandonment is forbidden, including when a
later trust or deadline check blocks invocation. The operation stays locked
until a separate, signed, journal-backed non-execution resolution or
reconciliation proves the disposition. A pre-acceptance expired release may be
closed only by signed `NotAccepted` evidence proving that no CA call occurred.

The state adapter records invocation durably before crossing the authority
boundary, and the CA journal makes the exact command at-most-once. The signed
CA outcome must report `executed_at` at or after that durable invocation time
and before the original authority-readiness and custody deadlines. Uncertainty
after invocation becomes `result-unknown`; reconciliation reads the signed CA
journal and never issues a second certificate.

PA completion requires two separately signed proofs: CA outcome evidence and a
manager commit receipt bound to the durable state revision and exact CA
evidence digest. `completed` and `not-executed` may resolve the corresponding
authorization; `still-unknown` retains the original lock. The state adapter's
durable outbox carries these proofs. Signing work is read before generating a
new random challenge, so crash recovery reuses the exact draft. Commit event
time is distinct from evidence issue time, with a signed bounded submission
deadline. The PA delivery outbox is deleted only after an exact durable ACK;
Coela never receives any evidence payload.

Integrity projection mismatches are sent to an independent alert sink. In
production that sink must not share the operation database, filesystem,
credentials, or failure domain.

## Deliberate production state

This crate ships port contracts and fail-closed `Unavailable*` adapters. It
does not ship a listener, software CA, in-memory production store, permissive
verifier, credential UI, or plaintext-key fallback. See
[CONTRACT.md](../docs/CONTRACT.md), [DEPLOYMENT.md](../docs/DEPLOYMENT.md), and
[SECURITY.md](../SECURITY.md).

Production adapters must provide authenticated IPC identity derivation, current
workload/device and custody verification, trusted monotonic time, exact revision
CAS, PA exact-ACK replay, non-exportable signing, and an idempotent signed CA
journal. Coela remains a local aggregation and operation-orchestration client;
it is not a substitute for any of those adapters.

The JSON schemas describe serialized V2 ingress envelopes and closed
service-facing response/status projections. Verified claims, reconciliation
contexts, and operation-state transactions remain Rust port types until a
separately reviewed authenticated IPC adapter defines their wire
representation.
