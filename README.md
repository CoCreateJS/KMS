# CoCreateKMS

**Tenant-scoped key management and portable cryptography for CoCreate.**

CoCreate KMS provides a managed server API for generating cryptographic keys, encrypting and decrypting application data, rotating key versions, and enforcing key lifecycle state. It also provides standalone Web Crypto and JOSE utilities for browser and Node applications.

## Install

```sh
npm install @cocreate/kms
```

## Managed server API

Initialize KMS once on a CoCreate server after CRUD is available. The server owns attaching the returned API:

```js
import KMS from "@cocreate/kms";

this.kms = KMS.init(this);
```

Pass the trusted tenant context resolved for the request. The same KMS service instance serves every tenant; key records and cache entries are scoped by organization and hostname.

```js
const key = await server.kms.generate({
  organization_id,
  host,
  name: "Application data"
});

const encrypted = await server.kms.encrypt({
  organization_id,
  host,
  _id: key._id,
  data: { message: "private" }
});

const result = await server.kms.decrypt({
  organization_id,
  host,
  data: encrypted.data,
  metadata: encrypted.metadata
});
```

KMS returns public key metadata without exposing key material. Encrypted values include metadata identifying the exact key version used, so decryption does not silently switch to a newer key.

### Managed key lifecycle

| Method | Purpose |
|---|---|
| `generate()` | Create the first key version for the current tenant. |
| `encrypt()` / `decrypt()` | Encrypt application data and decrypt it with its original key version. |
| `get()` / `set()` | Retrieve a key or place one in the local process cache. |
| `rotate()` | Create a new version in an existing key lineage. |
| `setExpiration()` | Set or clear a version’s expiration. |
| `revoke()` | Revoke a specific key version. |
| `delete()` | Mark a key version logically deleted. |
| `destroy()` | Clear local key material after explicit dependency confirmation. |
| `invalidate()` / `close()` | Clear cached keys or release KMS resources. |

Managed encryption uses AES-256-GCM envelope encryption. Key versions use unique identifiers and retain historical versions for decryption unless their lifecycle state prevents access. Rotation does not re-encrypt existing application data.

Managed key records are read and written through `server.crud.send()` in the `app` database's `keys` array, using `type: "cryptographic"`. Each request includes its `organization_id` and `host`. CRUD owns its in-memory data path, peer distribution, retries, and configured persistence. KMS treats a CRUD response without `error` (and without `success: false`) as success and does not wait for later persistence work. CRUD also owns `created` and `updated` metadata; KMS owns key-specific lifecycle fields.

The server context supplies tools such as CRUD and authorization. KMS does not resolve hostnames or infer a tenant from server-wide state. The HTTP/Cluster layer resolves hostname to organization before dispatch and supplies that tenant context to each managed KMS call.

### Server cryptography namespace

The Node server entry also exports `kms`, a synchronous namespace for cryptographic primitives, token, signature, encoding, and certificate-request helpers used by CoCreate server modules:

```js
import { kms } from "@cocreate/kms/server";

const pair = kms.generateKeyPair("rsa", { modulusLength: 2048 });
const token = kms.generateJWT({ header: { alg: "RS256" }, payload: { sub: "service" } }, pair.privateKey);
```

This namespace is separate from managed tenant key records and the portable Web Crypto API. Server integrations use `kms.*` helpers without initializing a managed KMS instance. Browser applications should use the portable `crypto`, `aes`, `jwt`, and related namespaces.

## Portable cryptography and JOSE

Portable utilities accept caller-supplied key bytes or Web Crypto `CryptoKey` objects. They are independent of managed key records and can be imported from the package root or the environment-specific subpaths.

```js
import KMS from "@cocreate/kms";

const key = await KMS.aes.generateKey();
const envelope = await KMS.aes.encrypt("private message", key, {
  aad: "record:123"
});
const plaintext = await KMS.aes.decrypt(envelope, key, {
  aad: "record:123"
});
```

`plaintext` is a `Uint8Array`. The portable AES-GCM envelope is `{ algorithm, iv, ciphertext, tag }`, which is distinct from the managed API’s `{ data, metadata }` result. Encryption creates a random 96-bit nonce internally and rejects a caller-supplied nonce. Use the same additional authenticated data (`aad`) when decrypting. Random nonce collisions remain probabilistically possible; deployments should set key-usage and rotation limits appropriate for AES-GCM.

The portable namespaces are `crypto`, `aes`, `sha256`, `ed25519`, `rsa.pss`, `encoding`, `jws`, `jwt`, and `jwk`. Supported algorithms are AES-128/256-GCM, SHA-256/384/512, HMAC, Ed25519, RSA-PSS/SHA-256, and JOSE HS256, PS256, and EdDSA. HS256 requires a key of at least 32 bytes. JWS verification requires an explicit expected algorithm and a trusted verification key.

JWT verification supports issuer, audience, subject, clock tolerance, and an optional required-expiration policy:

```js
const pair = await KMS.ed25519.generateKeyPair();
const now = Math.floor(Date.now() / 1000);
const token = await KMS.jwt.generate({
  iss: "my-service",
  aud: "my-app",
  exp: now + 300
}, pair.privateKey, { alg: "EdDSA" });

const claims = await KMS.jwt.verify(token, pair.publicKey, {
  alg: "EdDSA",
  issuer: "my-service",
  audience: "my-app",
  requireExp: true
});
```

Without `requireExp: true`, JWT verification validates `exp` when present but does not require the claim. Applications should select an expiration policy that fits their use case.

The package root resolves to a Node entry on Node and a browser entry in browser-aware bundlers. Explicit `@cocreate/kms/server`, `@cocreate/kms/browser`, and `@cocreate/kms/portable` imports are available. Browser use requires Web Crypto in a secure context; Node requires version 20 or newer.

## Scope and compatibility

The portable API does not implement OAuth, access-token issuance or rotation, PKCE, JWE, ES256, or certificate validation. The Node `kms` namespace carries the existing CoCreate server helper contracts, while the portable API is a smaller Web Crypto surface. Neither API migrates previously stored ciphertext or signatures. Review the [cryptography specification](specifications/cryptography.md) before integrating persisted formats or choosing key-retention policies.

See the [KMS specifications](specifications/README.md) for architecture, API, lifecycle, and cryptography contracts.
