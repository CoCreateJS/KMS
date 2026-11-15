# CoCreateKMS

**Cryptographic Key Management, Encryption, Decryption & Lifecycle Management**

CoCreate KMS generates and manages cryptographic keys, encrypts and decrypts application data, and handles key versions and lifecycle state. It keeps a private in-memory key cache. Configured CoCreate Workflows decide whether keys are stored, where they are stored, how they are encoded, and how they are fetched and decoded.

KMS does not directly call a database, filesystem, or storage provider. Workflows define how external services are used without changing the KMS runtime.

The normative contracts are in [`specifications/`](specifications/README.md).

## Initialize

Cluster attaches KMS to the server after its modules are initialized:

```js
import KMS from "@cocreate/kms";

this.kms = KMS.init(this);
```

Initialization performs no reads or writes. Storage and fetch workflows run only when a KMS operation reaches those points.

## API

All public methods accept one object argument.

| Method | Responsibility |
|---|---|
| `generate()` | Generate an initial key version. |
| `encrypt()` | Encrypt a value using a locally eligible key version. |
| `decrypt()` | Decrypt using the exact version identified in metadata. |
| `get()` | Resolve a key from memory, then the configured fetch workflow. |
| `set()` | Add a key to this process's memory cache only. |
| `invalidate()` | Clear a key or lineage from this process's cache. |
| `rotate()` | Generate a new version in an existing lineage. |
| `revoke()` | Mark a key version revoked. |
| `setExpiration()` | Set or clear a key version's expiration date. |
| `delete()` | Mark a key version logically deleted. |
| `destroy()` | Remove key material from KMS state after explicit confirmation. |

There are no KMS `read()` or `save()` APIs. Persistence and retrieval are workflow responsibilities.

### Generate and encrypt

```js
const key = await server.kms.generate({
  scopes: { organization_id, host },
  name: "Storage encryption",
  rotation: { interval: 86_400_000, delay: 60_000 }
});

const encrypted = await server.kms.encrypt({
  scopes: { organization_id, host },
  _id: key._id,
  data: { message: "private" }
});
```

`generate()` returns public metadata without key material. `encrypt()` returns `{ data, metadata }`; consumers decide how to store the encrypted value and metadata.

### Decrypt

```js
const result = await server.kms.decrypt({
  scopes: { organization_id, host },
  data: encrypted.data,
  metadata: encrypted.metadata
});
```

KMS resolves the exact version in `metadata.key`. It never substitutes a newer version.

## Workflow integration

Configure workflow names on the server:

```js
server.kmsConfig = {
  workflows: {
    store: "kmsStoreKey",
    fetch: "kmsFetchKey",
    verify: "kmsVerifyKey"
  }
};
```

The workflows run through `server.workflow.run()`.

### Store workflow

KMS calls `store` after generation, rotation, verification-state changes, revocation, deletion, destruction, and KMS-managed status changes. The workflow receives:

```js
{
  event: "key.generated",
  key: { /* KMS key document, including private keyMaterial */ },
  scopes
}
```

Events include `key.generated`, `key.rotated`, `key.verification-pending`, `key.activated`, `key.verification-failed`, `key.status-changed`, `key.expiration-changed`, `key.revoked`, `key.deleted`, and `key.destroyed`.

The workflow decides whether to persist the key and which mechanism, encoding, and protection to use. It may use any configured service or apply policy that declines persistence. Store workflows receive secret key material and must not log or expose it. A workflow error fails the KMS operation; KMS does not fall back to direct storage.

### Fetch workflow

On a cache miss, KMS calls `fetch` with either:

```js
data: { query: { _id }, scopes }
```

Return one decoded key document through `data.key`, or `null` when missing. For version lineage lookup, KMS sends:

```js
data: { query: { key: lineageRootId }, scopes }
```

Return decoded key documents through `data.keys`. Each returned record must include 32-byte `keyMaterial` as a Buffer/Uint8Array or base64url string. The workflow owns the lookup and decoding process.

Without a `fetch` workflow, cache misses return `null`. Without a `store` workflow, generated keys remain in process memory and are lost on restart.

### Verification workflow

`verify` is optional. It receives the candidate version in `data.key` as `{ _id, version, key }` and the operation scopes. It must return `data.verified: true` to approve activation. The workflow defines what availability or recovery checks are sufficient.

## Key identity and document shape

Every version has a unique ObjectId. `key` references its lineage root; the root's `key` equals its own `_id`. `name`, `description`, and `tags` are optional descriptions, not identifiers. There is no `purpose` property.

```js
{
  _id: "version-object-id",
  type: "cryptographic",
  key: "lineage-root-object-id",
  version: 1,
  algorithm: "AES-256-GCM",
  keyMaterial: "base64url-encoded-32-byte-key",
  status: "active",
  rotation: { interval: null, delay: 60000 },
  activates: { on: "ISO-8601 timestamp" },
  expires: { on: null },
  revoked: { on: null, by: null },
  deleted: { on: null, by: null }
}
```

This is the KMS in-memory shape. Store workflows may transform it. Fetch workflows must return this shape with decoded key material. Public results omit `keyMaterial`.

## Encryption format

KMS uses AES-256-GCM envelope encryption. It generates a unique random DEK per encrypted value, encrypts the value with the DEK, and wraps the DEK with the selected KEK version. Encryption metadata includes the exact key-version ObjectId, version, algorithm, encoding, nonce, authentication tag, and wrapped DEK. Authenticated metadata changes cause decryption to fail.

Plaintext key material stays in KMS process memory and in private workflow invocations. The workflow determines its at-rest protection. JavaScript strings cannot be reliably zeroized; temporary buffers are cleared where practical.

## Versioning and lifecycle

Rotation is manual or automatic through `rotation.interval` in milliseconds. `rotation.delay` defaults to 60 seconds. The previous eligible key remains in use while a new version waits for activation or verification. Historical versions are retained for decryption unless revoked, deleted, or destroyed by policy. Rotation does not re-encrypt consumer data.

KMS owns `activates`, `expires`, `revoked`, and `deleted`. The storage workflow/backend owns storage metadata such as `created` and `updated`; KMS does not synthesize those fields.

`destroy()` requires `confirm` to equal the version ObjectId and `dependenciesCleared: true`. This is a caller attestation, not a dependency scan. KMS clears the material from its local state and emits `key.destroyed`; the workflow decides how to remove or cryptographically erase external copies.

Automatic timers are process-local and best-effort. On restart, the next encryption operation fetches the lineage and re-arms rotation and pending verification. KMS does not provide distributed rotation coordination; separate processes may race on sequential version numbers.

## Scope, cache, and authorization

`scopes` is opaque context supplied to KMS and passed unchanged to workflows. `organization_id` and `host` identify the workflow tenant context when available. KMS uses scope context to isolate its local cache; it does not map scopes to storage-specific paths or queries.

`get()` is cache-first. `invalidate({ scopes, _id })` clears one lineage; omitting `_id` clears that scope's cache. Identified requests use the server authorization service before key access or workflow execution. Public methods never return plaintext key material.

## Recovery boundary

Recovery requires both an available key record and whatever provider credentials or decoding material the fetch workflow needs. Ciphertext alone cannot recreate a lost key. KMS does not mandate a database, persistence provider, replication mechanism, or backup policy.
