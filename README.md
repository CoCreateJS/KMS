# CoCreateKMS

**Organization-scoped key management and portable cryptography for CoCreate.**

CoCreate KMS provides a managed server API for generating cryptographic keys, encrypting and decrypting application data, rotating key versions, and enforcing key lifecycle state. It also provides standalone Web Crypto and JOSE utilities for browser and Node applications.

## Install

```sh
npm install @cocreate/kms
```

## Managed server API

Initialize KMS on a CoCreate server after the server’s core services:

```js
import KMS from "@cocreate/kms";

this.kms = KMS.init(this);
```

Generate a key for the organization, then encrypt and decrypt data with that key lineage:

```js
const key = await server.kms.generate({
  scopes: { organization_id, host },
  name: "Application data"
});

const encrypted = await server.kms.encrypt({
  scopes: { organization_id, host },
  _id: key._id,
  data: { message: "private" }
});

const result = await server.kms.decrypt({
  scopes: { organization_id, host },
  data: encrypted.data,
  metadata: encrypted.metadata
});
```

KMS returns public key metadata without exposing key material. Encrypted values include metadata identifying the exact key version used, so decryption does not silently switch to a newer key.

### Managed key lifecycle

| Method | Purpose |
|---|---|
| `generate()` | Create the first key version for an organization. |
| `encrypt()` / `decrypt()` | Encrypt application data and decrypt it with its original key version. |
| `get()` / `set()` | Retrieve a key or place one in the local process cache. |
| `rotate()` | Create a new version in an existing key lineage. |
| `setExpiration()` | Set or clear a version’s expiration. |
| `revoke()` | Revoke a specific key version. |
| `delete()` | Mark a key version logically deleted. |
| `destroy()` | Clear local key material after explicit dependency confirmation. |
| `invalidate()` / `close()` | Clear cached keys or release KMS resources. |

Managed encryption uses AES-256-GCM envelope encryption. Key versions use unique identifiers and retain historical versions for decryption unless their lifecycle state prevents access. Rotation does not re-encrypt existing application data.

Managed key retention is configured by the host application. Without a persistence integration, generated keys remain in process memory and do not survive a restart.

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

The portable API does not implement OAuth, access-token issuance or rotation, PKCE, JWE, ES256, or certificate validation. It does not replace the legacy security utilities or migrate their existing ciphertext or signatures. Review the [cryptography specification](specifications/cryptography.md) before integrating persisted formats or choosing key-retention policies.

See the [KMS specifications](specifications/README.md) for architecture, API, lifecycle, cryptography, and storage integration contracts.
