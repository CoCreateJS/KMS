# Architecture and Tenancy

## Service initialization

KMS is a server service, not a tenant-specific object factory. Cluster initializes it after CRUD is available and attaches the returned API:

```js
server.kms = KMS.init(server);
```

Calling `init()` again with the same server object returns the same API instance. The instance owns process-local caches and timers. Each worker or server process has its own instance and cache.

The server object supplies tools such as `server.crud` and authorization. It is not the tenant identity and KMS does not attach itself to the server; the caller performs that assignment.

## Tenant context

The HTTP/Cluster layer resolves the request hostname to an organization and passes trusted `organization_id` and `host` values to KMS. Every managed operation requires both values, either at the top level or within the accepted `scopes` context. KMS does not resolve hostnames, infer an organization from server-wide defaults, or select a tenant at initialization.

Every CRUD envelope includes the operation's `organization_id` and `host`. Key cache entries are isolated by that same pair, so a key cached for one tenant cannot satisfy a request for another tenant. Callers must only pass trusted tenant context established by the host application.

## Data operations

KMS uses `server.crud.send()` directly for managed key records in the `app` database and `keys` array. Records are distinguished by `type: "cryptographic"` and include a tenant's organization identity. KMS performs reads, creates, and updates needed by its API. It does not implement a database, provider adapter, replication process, or separate persistence path.

CRUD handles its in-memory data path, peer distribution, retries, and configured persistence. KMS considers the request successful when CRUD returns without `error` and without `success: false`; it does not wait for later persistence or peer work.

CRUD owns database-managed `created` / `updated` metadata. KMS owns cryptographic material, key versions, activation, expiration, revocation, and logical deletion metadata.

## Portable cryptography

Portable Web Crypto and JOSE utilities accept caller-supplied key material and do not use the managed key store. They can be used independently of a CoCreate server.
