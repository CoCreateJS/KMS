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
