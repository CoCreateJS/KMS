# Architecture and Responsibility

## KMS owns

- Secure key generation and in-process key access.
- Encryption, decryption, key versions, rotation, activation, expiration, revocation, logical deletion, and key destruction requests.
- A private in-memory `Map` keyed by the exact key-version ObjectId.
- Public result sanitization so plaintext key material is not returned from API methods.

KMS does not own persistence, database access, provider selection, serialization for storage, replication, or distributed coordination.

## Workflows own

Configured workflows decide whether key material is stored, where it is stored, how it is encoded or protected at rest, how records are retrieved and decoded, and how storage-specific lifecycle operations are performed. A workflow may use any configured service or no storage at all.

KMS passes key records and lifecycle events to the configured workflow contract. It does not call persistence providers directly and does not assume the shape of their data APIs.

## Initialization and scope

Cluster attaches KMS with `this.kms = KMS.init(this)`. Initialization performs no persistence operations. Storage workflows are invoked only when a KMS API operation reaches a documented storage or retrieval point.

KMS uses `organization_id`, `host`, and opaque `scopes` to identify the tenant context for authorization, workflow execution, and cache isolation. KMS does not map scopes to a storage-specific location or query.

## Workflow configuration

Workflow names are supplied on the server:

```js
server.kmsConfig = {
  workflows: {
    store: "kmsStoreKey",
    fetch: "kmsFetchKey",
    verify: "kmsVerifyKey"
  }
};
```

`store` and `fetch` are optional. Without `store`, generated and rotated keys remain process-local. Without `fetch`, a cache miss returns no key. `verify` is optional and is required only when a key's rotation policy requests verification.

The named workflows are invoked through `server.workflow.run()`. Their precise payload and result contract is defined in [Workflow Usage](workflow-usage.md).

## Security boundary

Workflow store requests contain plaintext key material so the workflow can apply the configured storage encoding/protection. Workflows must not log or expose that material. Fetch workflows must return usable 32-byte key material to KMS in process memory. KMS API return values omit the material.

When a request has `user_id` or `apikey`, KMS uses the server authorization service for the corresponding KMS operation. Internal calls without request identity are trusted server-to-server operations.
