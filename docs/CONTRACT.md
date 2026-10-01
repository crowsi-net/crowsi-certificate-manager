# V2 service contract

## Boundary

| Concern | Owner |
| --- | --- |
| redacted aggregation, intent display and local call orchestration | Coela Control |
| minimal authenticated lifecycle interface | each authorized service adapter |
| policy decision and one-use execution lease | PA/PEP |
| service leaf private key | service-local custody provider |
| certificate lifecycle and reconciliation | Crowsi Certificate Manager |
| CA signing and authoritative journal | Crowsi authority adapter |
| durable-commit evidence signing | manager-only key-provider adapter |
| released authorization acceptance | manager-handoff signer and authenticated PA adapter |
| replay, lifecycle CAS, audit and outbox | atomic operation-state adapter |
| dual-evidence PA completion delivery | authenticated outbox worker |
| projection-corruption alert | independent integrity sink |

The logical service ID is `crowsi-certificate-manager`; the only production
transport is authenticated `native-ipc`. There is no external listener.
Services call the minimal lifecycle interface directly. Coela submits an opaque
intent to a service-owned adapter and receives only a dispatch acknowledgement
and redacted operation status. It never calls the manager interface, and has no
private certificate-management API or signing authority.

Before every CA operation, the PA release remains
`released-pending-accept`. `CertificateManagerHandoffPort` receives only an
exact durable operation readback, journals its signing attempt, independently
verifies the dedicated P-256 evidence, and obtains an exact PA ACK. Coela is
not a participant in this payload path.

## APIs

| API | PA action | CA access | Key custody input |
| --- | --- | --- | --- |
| `execute_mutation` issue | `issue` | issue | required |
| `execute_mutation` renew | `renew` | renew | required |
| `execute_mutation` revoke | `revoke` | revoke | forbidden |
| `certificate_status` | `certificate-status` | read | forbidden |
| `operation_status` | `operation-status` | none | forbidden |
| `reconcile_unknown` | `reconcile-unknown` | journal only | forbidden |

Operation status cannot be upgraded to reconciliation. Reconciliation binds the
original action, operation, resource, owner, version, reservation, authority
command digest, lifecycle fences, and lifecycle epochs.

Every call and resume requires current IPC-derived workload and device
authentication. Issue and renew additionally require a current custody
attestation stably bound to the original CSR/SPKI and workload. Revoke,
certificate status, operation status, and reconciliation require custody input
to be absent.

Issue, renew, revoke, and reconciliation require complete fresh signed
user-presence evidence and separation of requester and approver. Certificate
and operation status require all approval fields to be absent. The verifier
derives these flattened fields from the signed evidence; they are not an
authorization substitute.

Every request uses a provider-scoped canonical resource ID. Authorization
binds the pinned normalizer ID, opaque version, and normalization proof digest.
The canonical ID—not a raw provider alias—is the lifecycle CAS and fence key.
`deployment_provenance_ref` is non-authorizing provenance; `pa_reservation_id`
is the only one-use PA reservation.

## Serialized V2 ingress

- `crowsi://certificates/management-command/v2`
- `crowsi://certificates/execution-authorization/v2`
- `crowsi://certificates/key-custody-attestation/v2`
- `crowsi://certificates/authority-readiness-attestation/v2`
- `crowsi://certificates/authority-outcome-receipt/v2`
- `crowsi://certificates/authority-reconciliation-receipt/v2`
- `crowsi://certificates/management-response/v2`
- `crowsi://certificates/operation-status/v2`
- `crowsi://certificates/reconciliation-response/v2`

`WorkloadEvidenceV2` is adapter-created and has no service-facing JSON schema.
Verified objects and state transactions are Rust port contracts; an adapter
must define and review any additional serialization. Management responses may
contain public certificate bytes only on the authenticated service channel.
Operation status is the metadata-only projection intended for Coela.
Its policy and operator fields are opaque immutable references and digests, not
the underlying authorization or approval payloads.

## State transitions

```text
PA reserved -> released-pending-accept -> executing
                                      -> abandoned (signed NotAccepted only)

reserved -> abandoned
reserved [handoff-pending -> handoff-accepted/pending-invocation]
reserved -> invoked -> finalized
                    -> result-unknown
result-unknown -> finalized
               -> reconciled-not-executed
               -> result-unknown
```

Only pre-acceptance `reserved` state may be generically abandoned. Once PA
`Accepted` is durable, neither a timeout, restart, trust failure, nor missed
deadline may abandon it. A separate signed, journal-backed non-execution
resolution/reconciliation must prove the disposition. Completed reconciliation
can recover a finalization ACK loss but must never reissue.

Every transition compares and advances the exact operation-row revision.
Staged is the source revision plus one, accepted plus two, invoked plus three;
later transitions continue exact CAS. Repeated, skipped, stale, or overflowing
revisions fail closed. Every returned projection contains the exact durable
revision and recorded proof digests.

The bracketed handoff states are durable substates of `reserved`. The state
adapter writes `handoff-pending` before PA contact and CAS-writes accepted
evidence before invocation. Exact resume lookup runs before fresh preflight,
so a PA ACK recorded before lease expiry remains recoverable after that expiry.
Resume is limited by `max_handoff_recovery_seconds`, repeats current PA
revocation/trust, current authenticated workload/device, current
issue-or-renew custody, and CA-readiness verification. The full staged
`AuthorityCommandV2` is re-derived from the original command and verified
sources, then compared exactly.

The manager reads trusted time and snapshots those verified values immediately
before PA acceptance. After exact ACK and durable accepted CAS, it reads trusted
time again and purely revalidates the snapshot before recording invocation.
Only the PA authorization expiry may cross inside the bounded recovery window.
The original authority-readiness and custody deadlines are never extended.

The operation row records `invoked_at` before the CA boundary. The authority
adapter executes the canonical command at most once and signs its journaled
`executed_at`. The manager accepts the outcome only when `executed_at` is at or
after durable `invoked_at` and before every applicable original deadline.

PA completion consumes a signed authority-outcome evidence document and a
separately signed manager-commit evidence document. The commit document binds
the exact authority evidence digest and durable revision. For reconciliation,
`completed` and `not-executed` resolve the original lock according to their
state transition; `still-unknown` consumes only the reconciliation attempt and
leaves the original operation locked.

The completion worker first reads a persisted signing attempt. It generates a
random nonce only for a new attempt, stages both proofs atomically, and then a
separate delivery worker retries PA submission by commit ID. The delivery row
is acknowledged only when authorization JTI, commit ID, both evidence digests,
disposition, and the signed recovery window all match.
