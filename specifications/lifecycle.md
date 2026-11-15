# Lifecycle, Rotation, and Recovery

## Lifecycle metadata

KMS manages `activates.on`, `expires.on`, `revoked.on` / `.by`, and `deleted.on` / `.by`. It does not synthesize storage-system metadata such as `created` or `updated`; a storage workflow or its backend owns those fields and may return them with fetched records.

`setExpiration({ scopes, _id, on })` changes `expires.on`; `on: null` clears it. The change is emitted through the store workflow as `key.expiration-changed`. Expiration affects use of that exact key version but does not delete its record or material.

By default, encryption requires an active, non-expired, non-revoked, non-deleted version whose activation time has arrived and whose required verification succeeded. Decryption resolves the exact referenced version; expired or revoked versions require explicit `allowExpired: true` / `allowRevoked: true`. Deleted and destroyed versions cannot decrypt.

## Versioning and rotation

Rotation reads the key lineage through the configured fetch workflow, selects `max(version) + 1`, creates a new unique ObjectId, and keeps the lineage root in `key`. It emits a `key.rotated` store event. Existing versions remain available for historical decryption unless policy revokes, deletes, or destroys them. Rotation does not re-encrypt consumer data.

`rotation.interval` is milliseconds; null disables automatic rotation. `rotation.delay` defaults to 60 seconds. New versions remain pending until the activation time and any requested verification succeed. Timer scheduling is process-local. On restart, the next encryption request fetches the lineage and re-arms automatic rotation and pending verification. Timers are best-effort, not a durable job queue.

Concurrent rotations are serialized within one process. Multiple processes may race when assigning sequential version numbers; KMS does not provide distributed coordination.

## Availability verification

Verification can be enabled with `verify: true`, a workflow name, or `{ workflow, timeout, retryInterval }`. The configured verification workflow receives the exact candidate version and scopes. It must return `data.verified: true`, and if it returns `data.key` or `data.version`, those values must match. Pending or failed verification leaves that version ineligible; KMS continues using the previous eligible version.

Verification means whatever the configured workflow checks. It may confirm recoverability, provider availability, or a policy-specific condition. KMS does not infer durability from workflow success.

## Revocation, deletion, and destruction

Revocation blocks new encryption by default and emits `key.revoked`. Historical decryption can be explicitly allowed. Logical deletion marks a version, emits `key.deleted`, and retains key material in KMS state for any permitted historical use. Neither action automatically cascades across a lineage.

`destroy()` requires `confirm` to equal that version's ObjectId and `dependenciesCleared: true`. The latter is a caller attestation, not an automated dependency scan. KMS removes the material from its local state and emits `key.destroyed` with `keyMaterial: null`; the store workflow determines how to remove or cryptographically erase external copies. Physical erasure from provider backups or media is outside KMS.

## Recovery

Recovery depends on the configured fetch workflow and the availability of whatever credentials or decoding material that workflow needs. Ciphertext alone cannot recreate a lost key. KMS does not mandate a database, provider, replication mechanism, or backup policy.
