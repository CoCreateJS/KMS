# Lifecycle, Rotation, and Recovery

## Lifecycle metadata

KMS manages `activates.on`, `expires.on`, `revoked.on` / `.by`, and `deleted.on` / `.by`. It does not generate or manage database-owned `created` and `updated` metadata. CRUD manages those fields.

`setExpiration({ organization_id, host, _id, on })` changes `expires.on`; `on: null` clears expiration. Expiration affects use of that key version but does not delete its record or material.

By default, encryption requires an active, non-expired, non-revoked, non-deleted version whose activation time has arrived and whose optional verification succeeded. Decryption resolves the exact referenced version; expired or revoked versions require `allowExpired: true` / `allowRevoked: true`. Deleted and destroyed versions cannot decrypt.

## Versioning and rotation

Rotation reads the tenant-scoped key lineage through CRUD, selects `max(version) + 1`, creates a new version record, and keeps the lineage root in `key`. Existing versions remain available for historical decryption unless policy revokes, deletes, or destroys them. Rotation does not re-encrypt consumer data.

`rotation.interval` is milliseconds; null disables automatic rotation. `rotation.delay` defaults to 60 seconds. New versions remain pending until activation and any requested verification succeed. Timer scheduling is process-local and best-effort, not a durable job queue. On restart, a caller can request the lineage again through KMS to re-arm its timers.

Concurrent rotations are serialized within one process. Multiple processes may race when assigning sequential version numbers; KMS does not provide distributed coordination.

Optional availability verification is a server-configured or per-call callback. It receives the candidate key metadata and tenant context, and must return `true` or `{ verified: true }`. Verification callbacks must not expose key material. KMS does not infer durability from callback success.

## Revocation, deletion, and destruction

Revocation blocks new encryption by default and updates the record in CRUD. Historical decryption can be explicitly allowed. Logical deletion marks a version in CRUD while retaining its material for any permitted historical use. Neither action automatically cascades across a lineage.

`destroy()` requires `confirm` to equal that version's ObjectId and `dependenciesCleared: true`. The latter is a caller attestation, not an automated dependency scan. KMS clears local key material and updates the CRUD record with `keyMaterial: null` and `destroyed: true`. Physical erasure from provider backups or media is outside KMS.

## Recovery

Managed key recovery reads the tenant's record through CRUD. CRUD and CoCreateDB own the configured data and persistence lifecycle. Ciphertext alone cannot recreate a lost key. KMS does not implement a separate database, provider, replication mechanism, or backup policy.
