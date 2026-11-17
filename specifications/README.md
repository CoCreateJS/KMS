# CoCreateKMS Specifications

These documents define the managed KMS contract and its portable cryptography API.

- [Architecture and tenancy](architecture.md): initialization, server context, tenant scope, and CRUD responsibility.
- [API and key records](api.md): methods, arguments, CRUD operations, and key-version documents.
- [Cryptography and key material](cryptography.md): envelope format, authenticated metadata, and secret handling.
- [Lifecycle and recovery](lifecycle.md): versioning, activation, rotation, expiration, revocation, deletion, and destruction.

CoCreate KMS manages cryptographic operations and key lifecycle. Managed key records are accessed through `server.crud.send`; CRUD and CoCreateDB own data handling and persistence. The Node server entry also provides the `kms` helper namespace for server-side key, token, signature, and certificate utilities.
