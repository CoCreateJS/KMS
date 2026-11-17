# [1.1.0](https://github.com/CoCreateJS/kms/compare/v1.0.0...v1.1.0) (2026-11-17)


### Features

* add portable cryptography APIs ([2316d92](https://github.com/CoCreateJS/kms/commit/2316d9273542e606e7932d7c7ad32bbab2c317e5))

# 1.0.0 (2026-11-15)


### Features

* initial CoCreate KMS release ([9a0b397](https://github.com/CoCreateJS/kms/commit/9a0b3973b7b5be165969e4547858405abe535bf5))

# Changelog

## Unreleased

- Add the CoCreateKMS server API for key generation, AES-256-GCM envelope encryption, decryption, in-memory caching, rotation, verification, and lifecycle management.
- Route managed key reads, writes, and lifecycle updates through tenant-scoped CoCreate CRUD envelopes.
- Reuse one KMS API per server context while isolating managed cache entries by organization and hostname.
- Document the normative KMS architecture, API, cryptography, and lifecycle contracts in `specifications/`.
- Add Cluster initialization for CoCreateKMS.
