# CoCreateKMS Specifications

These documents define the managed KMS contract. The package [README](../README.md) is the usage guide for both managed KMS and the portable cryptography API. Managed KMS owns organization-scoped key lifecycle and its in-memory cache; configured workflows own managed-key retrieval, storage, serialization, and persistence behavior. Portable utilities use caller-supplied keys and do not access managed records.

## Specifications

- [Architecture and scope](architecture.md): component boundaries, key scope, initialization, and trust assumptions.
- [API and key records](api.md): public methods, arguments, results, and key-version documents.
- [Cryptography and key material](cryptography.md): envelope format, authenticated metadata, and secret handling.
- Portable Web Crypto utilities and the JOSE/JWT subset are documented in the package [README](../README.md#portable-cryptography-and-jose); these utilities are independent of managed key persistence.
- [Lifecycle and recovery](lifecycle.md): versioning, activation, rotation, verification, expiration, revocation, deletion, and destruction.
- [Workflow usage](workflow-usage.md): workflow configuration, invocation payloads, return values, and failure handling.

These specifications describe KMS only. A workflow may use any configured service or no persistent storage. Those choices do not change the KMS runtime contract.
