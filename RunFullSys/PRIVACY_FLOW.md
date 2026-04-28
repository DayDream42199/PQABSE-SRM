## Cloud Privacy Flow

This prototype now uses a narrower CS-side trust surface for the mobile query flow:

- `TA` still prepares the authentication package and returns the local proving witness material to the client.
- The client generates the ZK proof locally and sends the proof artifacts, signed auth token, shortlist trapdoor, and optional preferred-label token to `CS`.
- `CS` verifies the signed token and ZK proof against the public registration and revocation roots.
- `CS` no longer needs mirrored per-user runtime files such as `.cred` or `_userkey.bin` for the mobile cloud query path.

## Bundle Storage Changes

- `CS` now stores ciphertext bundles under opaque random bundle IDs.
- The on-disk metadata no longer stores:
  - human-readable bundle labels
  - owner GIDs
  - explicit ciphertext file paths as primary metadata
- `CS` keeps only the minimal metadata needed for search and revocation handling:
  - opaque bundle ID
  - deterministic preferred-label token
  - epoch
  - registration root
  - revocation root
  - re-encryption flag

## Metadata Still Visible

The current prototype still intentionally exposes some operational metadata to `CS`:

- opaque bundle IDs
- epoch/version information
- registration and revocation Merkle roots
- whether a bundle has been lazily re-encrypted
- access-pattern information inherent to serving a matching bundle

The preferred-label token is deterministic, so it hides the raw label from direct display/storage at `CS`, but it is still susceptible to offline guessing if the label space is small.

## Compatibility Notes

- The mobile app can send `preferred_label_token` instead of a raw preferred label on the modern CS query path.
- `CS` keeps a raw-label fallback for older request formats to avoid breaking existing scripts immediately.
- Legacy CLI-style flows that depended on mirrored `CS/runtime/users` state may need follow-up refactoring if they are still in active use.
