# API and Key Records

All public KMS methods accept one object argument. `init(server)` returns the API; `close()` releases local timers and cached key records.

## Methods

| Method | Responsibility |
|---|---|
| `generate({ scopes, name?, description?, tags?, rotation?, expires? })` | Generate version 1, invoke the configured store workflow, cache the key, and return public metadata. |
| `encrypt({ scopes, _id, data, context? })` | Resolve the newest locally eligible version and return ciphertext plus metadata. |
| `decrypt({ scopes, data, metadata, allowExpired?, allowRevoked? })` | Resolve the exact version in `metadata.key` and decrypt. |
| `get({ scopes, _id })` | Resolve an exact key version from the local Map, then the configured fetch workflow. |
| `set({ scopes, key })` | Cache a key in this process only. It does not invoke a storage workflow. |
| `invalidate({ scopes, _id? })` | Remove a key or lineage from this process's cache after external lifecycle changes. |
| `rotate({ scopes, _id, delay?, verify? })` | Generate and store a new version in the same lineage. |
| `revoke({ scopes, _id, by? })` | Revoke the specified version and invoke the store workflow with a lifecycle event. |
| `setExpiration({ scopes, _id, on })` | Set or clear the expiration date and invoke the store workflow. Pass `on: null` to clear expiration. |
| `delete({ scopes, _id, by? })` | Mark the specified version logically deleted and invoke the store workflow. |
| `destroy({ scopes, _id, confirm, dependenciesCleared })` | Remove key material from KMS state and notify the store workflow after explicit confirmation. |

KMS has no public `read()` or `save()` method. Cache misses and lifecycle persistence are handled by the configured fetch/store workflows.

## Key record

Each version is a separate document-shaped value with a unique ObjectId:

```js
{
  _id: "24-hex-object-id-for-this-version",
  type: "cryptographic",
  key: "24-hex-object-id-for-lineage-root",
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

This is KMS's in-memory key shape. A store workflow may transform it into any storage representation. A fetch workflow must return the KMS shape with decoded key material.

The lineage root has `key` equal to its own `_id`; later versions point to that root. `metadata.key` in ciphertext identifies the exact version document. `name`, `description`, and `tags` are optional descriptions, never identifiers. `purpose` is not part of the KMS key contract.

Public methods return key metadata without `keyMaterial`. `set()` accepts a secret-bearing record only for trusted server-side use.
