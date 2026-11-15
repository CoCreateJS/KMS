# Workflow Usage

KMS uses named CoCreate Workflows as its extension boundary. A workflow may use any configured service; KMS does not know or depend on the workflow's underlying persistence API.

## Configuration

```js
server.kmsConfig = {
  workflows: {
    store: "kmsStoreKey",
    fetch: "kmsFetchKey",
    verify: "kmsVerifyKey"
  }
};
```

Names are workflow names resolved by `server.workflow.run()`. `store` and `fetch` are optional. Without a store workflow, keys are process-local and disappear on restart. Without a fetch workflow, a cache miss returns `null`. A workflow failure is returned as a KMS error; KMS does not silently fall back to another storage mechanism.

## Store workflow

KMS calls the configured `store` workflow after key creation, rotation, verification-state changes, revocation, deletion, destruction, and KMS-managed status changes.

Invocation:

```js
{
  method: "workflow.<configured-name>",
  organization_id,
  host,
  data: {
    event: "key.generated",
    key: { /* KMS key document, including private keyMaterial */ },
    scopes
  }
}
```

The event values are `key.generated`, `key.rotated`, `key.verification-pending`, `key.activated`, `key.verification-failed`, `key.status-changed`, `key.expiration-changed`, `key.revoked`, `key.deleted`, and `key.destroyed`. The workflow may persist the key, transform its representation, route it to multiple destinations, or apply policy that declines persistence. If it reports an error, the KMS operation fails and does not publish the changed key into its local cache.

The store workflow receives plaintext key material for storage-policy processing. It is responsible for protecting it at rest as required and must not log or expose it.

## Fetch workflow

On a cache miss, KMS calls the configured `fetch` workflow with either an exact ObjectId query or a lineage query:

```js
data: { query: { _id }, scopes }
// Return through data.key: one KMS key document, or null.

data: { query: { key: lineageRootId }, scopes }
// Return through data.keys: an array of KMS key documents.
```

The workflow owns lookup, access to any storage system, and decoding. It must return `type: "cryptographic"` records with a valid ObjectId, lineage reference, version, and 32-byte `keyMaterial` as a Buffer/Uint8Array or base64url string. KMS validates and caches returned records. An exact lookup returning a different ObjectId is rejected.

## Verification workflow

Verification receives `data.key` containing `{ _id, version, key }` and the supplied scopes. It returns `data.verified: true` only after its configured check succeeds. Optional `data.key` and `data.version` results must match the candidate version. Verification does not imply durability unless the workflow verifies the deployment's recovery policy.

## Scope and authorization

Workflow invocations receive `organization_id`, `host`, and the caller's opaque `scopes`. KMS uses these values for workflow routing, authorization, and cache isolation; it does not translate them into storage-specific queries or locations. Identified user/API-key requests are authorized through the server authorization service before workflow execution.
