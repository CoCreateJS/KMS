# CoCreateKMS Specifications

These documents define the KMS contract. The package [README](../README.md) is the usage guide. KMS owns key generation, cryptographic operations, lifecycle, and an in-memory cache. Configured workflows own key retrieval, storage, serialization, and any persistence or replication behavior.

## Specifications

- [Architecture and scope](architecture.md): component boundaries, key scope, initialization, and trust assumptions.
- [API and key records](api.md): public methods, arguments, results, and key-version documents.
- [Cryptography and key material](cryptography.md): envelope format, authenticated metadata, and secret handling.
- [Lifecycle and recovery](lifecycle.md): versioning, activation, rotation, verification, expiration, revocation, deletion, and destruction.
- [Workflow usage](workflow-usage.md): workflow configuration, invocation payloads, return values, and failure handling.

These specifications describe KMS only. A workflow may use any configured service or no persistent storage. Those choices do not change the KMS runtime contract.
