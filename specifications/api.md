# API and Key Records

All public methods accept one object argument. `init(server)` returns a stable API object for that server context. Every managed operation requires a trusted `organization_id` and `host`, supplied at the top level or in `scopes`.

## Methods

| Method | Responsibility |
|---|---|
| `generate({ organization_id, host, name?, description?, tags?, rotation?, expires? })` | Generate and create version 1 in CRUD, cache its material, and return public metadata. |
| `encrypt({ organization_id, host, _id, data, context? })` | Resolve the newest eligible version and return ciphertext plus metadata. |
| `decrypt({ organization_id, host, data, metadata, allowExpired?, allowRevoked? })` | Read the exact referenced version and decrypt. |
| `get({ organization_id, host, _id })` | Resolve an exact version from the tenant-scoped cache or CRUD. |
| `set({ organization_id, host, key })` | Add a trusted server-side key record to the tenant-scoped local cache. |
| `invalidate({ organization_id, host, _id? })` | Remove a key or lineage from this process's cache after an external lifecycle change. |
| `rotate({ organization_id, host, _id, delay?, verify? })` | Read a lineage, create a new version in CRUD, and preserve historical versions. |
| `revoke({ organization_id, host, _id, by? })` | Update the version's revocation metadata in CRUD. |
| `setExpiration({ organization_id, host, _id, on })` | Set or clear expiration in CRUD; pass `on: null` to clear it. |
| `delete({ organization_id, host, _id, by? })` | Mark the version logically deleted in CRUD. |
| `destroy({ organization_id, host, _id, confirm, dependenciesCleared })` | Clear local key material and update the record after explicit confirmation. |

`close()` releases local timers and cached key records. It also clears the singleton registration for that server object so it can be initialized again.

## CRUD contract

Managed records are stored in `database: "app"`, `array: "keys"`, with `type: "cryptographic"`. KMS uses `object.read` for exact versions and lineages, `object.create` for newly generated versions, and `object.update` for lifecycle changes. Each envelope carries the request's `organization_id` and `host`.

KMS treats a CRUD response containing `error` or `success: false` as failure. A response without either is success; KMS does not wait for CRUD's subsequent distribution or persistence work. CRUD-generated `created` and `updated` metadata is left to CRUD.

Key material is included in the managed CRUD record and is never included in KMS's public key metadata result. Protect access to the shared `keys` array using the host application's authorization policies.

## Key record

Each version is a separate document with a unique ObjectId:

```js
{
  _id: "24-hex-object-id-for-this-version",
  type: "cryptographic",
  organization_id: "tenant-object-id",
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

The lineage root has `key` equal to its own `_id`; later versions point to that root. `metadata.key` in ciphertext identifies the exact version document. `name`, `description`, and `tags` are optional descriptions, never identifiers. Public methods return metadata without `keyMaterial`.
