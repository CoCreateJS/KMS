# Cryptography and Key Material

## Key generation and envelope encryption

The initial algorithm is AES-256-GCM. Each KMS key version contains a random 32-byte KEK. Each encrypted value receives an independent random 32-byte DEK. KMS encrypts the value with the DEK and wraps the DEK with the selected KEK.

KMS generates key material and uses it in process. KMS does not define how the KEK is encoded or protected when a workflow stores it. The store workflow may encrypt, wrap, encode, or route the key using deployment-specific policy. The fetch workflow retrieves and decodes it before returning it to KMS.

## Ciphertext format

`encrypt()` returns `{ data, metadata }`. `data` is base64url ciphertext. Metadata includes:

```js
{
  format: 1,
  key: "exact-version-object-id",
  version: 1,
  algorithm: "AES-256-GCM",
  encoding: "string | json | buffer",
  context: null,
  iv: "...",
  tag: "...",
  wrappedDEK: "base64url-encoded JSON AES-GCM envelope"
}
```

The data AES-GCM additional authenticated data binds `format`, `key`, `version`, `algorithm`, `encoding`, and `context`. The wrapped-DEK additional authenticated data binds it to the exact KMS key version and the `wrap-DEK` operation. Tampering with ciphertext, tags, version identity, or authenticated metadata causes decryption to fail.

`decrypt()` resolves only the exact version in `metadata.key`; it never substitutes another version. Missing or destroyed historical keys are errors.

## Secret handling

Plaintext key material is held in KMS process memory and is not returned from public methods. Store workflows receive a secret-bearing key record by design so they can apply deployment policy. They must avoid logging the record and must return decoded 32-byte material only to authorized KMS operations. JavaScript strings and garbage-collected copies cannot be reliably zeroized; temporary buffers are cleared where practical.

## Portable Web Crypto API

The portable API in `src/portable/` is separate from the managed key-record API. It accepts raw bytes or `CryptoKey` values supplied by the caller and performs no organization lookup, persistence, key rotation, or workflow invocation.

The exported namespaces are `crypto`, `aes`, `sha256`, `ed25519`, `rsa.pss`, `encoding`, `jws`, `jwt`, and `jwk`. Supported primitives are AES-128-GCM and AES-256-GCM; SHA-256, SHA-384, SHA-512; HMAC; Ed25519; and RSA-PSS with SHA-256. JOSE supports only HS256, PS256, and EdDSA. JWS verification requires an explicit expected algorithm matching the protected header and a trusted key supplied by the caller. CryptoKey type, permitted usage, and hash are checked against that algorithm. HS256 keys must be at least 256 bits. Empty JWS payloads are supported.

Portable AES encryption returns `{ algorithm, iv, ciphertext, tag }`, with Base64URL-encoded fields. The nonce is 12 random bytes and the tag is 16 bytes. Encryption generates the nonce internally and rejects caller-supplied nonces. Random nonce collisions remain probabilistically possible, so deployments must set key-usage and rotation limits appropriate for AES-GCM. The same AAD must be supplied for decryption. Decryption returns plaintext bytes. Keys and ciphertext are not managed or stored by these functions.

Base64URL decoding rejects noncanonical encodings. JWT verification checks expiration when an `exp` claim is present; set `requireExp: true` to reject tokens without that claim. Issuer, audience, and subject are checked when configured in the verification call. OAuth, access-token issuance or rotation, PKCE, JWE, ES256, and certificate validation are outside this API.

Browser builds use `globalThis.crypto` and require a secure context with Web Crypto. The Node entry uses `node:crypto` Web Crypto. These APIs are asynchronous except for encoding operations. The supplied tests exercise Web Crypto under Node; browser entry import was smoke-checked in Node, but a real browser run remains outstanding.
