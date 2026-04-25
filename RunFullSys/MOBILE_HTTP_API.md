# Mobile HTTP API

This document describes the current mobile-facing HTTP contract in the `httpnitro` branch. It is the backend target for the new Android application.

The mobile app owns the `MDO` and `MDU` roles. AWS hosts:

- `TA+IA+Blockchain`
- `Edge node`
- `CS`

The trusted parts of `TA` and `Edge` may run in Nitro Enclaves, but that does not change the HTTP API shape seen by the mobile app.

## Base services

- TA / IA service: `http://<ta-host>:8081`
- Edge service: `http://<edge-host>:8082`
- CS service: `http://<cs-host>:8083`

All mobile endpoints use JSON requests and JSON responses.

## TA / IA mobile API

### `GET /mobile/state`

Purpose:
- retrieve current system state for MDU bootstrap or refresh

Example response:

```json
{
  "status": "ok",
  "blockchain_state": {
    "epoch": 1,
    "registration_root": "abc",
    "revocation_root": "def"
  },
  "cloud_rekey_state": {
    "epoch": 1,
    "re_encryption_key": "base64-or-text",
    "update_token_seed": "seed",
    "revoked_user_gid": ""
  }
}
```

Notes:
- `cloud_rekey_state` may be `null` if no rekey state exists yet.

### `POST /mobile/register`

Purpose:
- register an MDU/mobile user
- issue user credential material
- return the current state needed to initialize local mobile state

Request:

```json
{
  "gid": "Alice",
  "attributes": ["doctor", "cardiology"]
}
```

Response:

```json
{
  "status": "ok",
  "stdout": "...",
  "stderr": "",
  "user": {
    "gid": "Alice",
    "identity_secret": 12345,
    "local_epoch": 1,
    "attributes": ["doctor", "cardiology"],
    "user_key_base64": "..."
  },
  "blockchain_state": {
    "epoch": 1,
    "registration_root": "abc",
    "revocation_root": "def"
  },
  "cloud_rekey_state": null
}
```

Important:
- `user_key_base64` is the serialized user secret key package returned by the backend.
- the Android app should persist the returned user package and system state locally.

## Edge mobile API

### `GET /mobile/state`

Purpose:
- retrieve current blockchain state from the Edge role

Example response:

```json
{
  "status": "ok",
  "blockchain_state": {
    "epoch": 1,
    "registration_root": "abc",
    "revocation_root": "def"
  }
}
```

### `POST /mobile/encrypt`

Purpose:
- perform the current mobile-to-Edge encryption handoff for `MDO`
- send owner context, plaintext, keywords, and policy
- receive the generated ciphertext bundle package back

Request:

```json
{
  "owner_gid": "Alice",
  "label": "demo1",
  "plaintext": "hello world",
  "keywords": ["heart", "report"],
  "policy_type": "and",
  "threshold": 1,
  "policy_attrs": ["doctor", "cardiology"]
}
```

Response:

```json
{
  "status": "ok",
  "stdout": "...",
  "stderr": "",
  "blockchain_state": {
    "epoch": 1,
    "registration_root": "abc",
    "revocation_root": "def"
  },
  "bundle": {
    "bundle_label": "demo1",
    "bundle_meta": {
      "bundle_label": "demo1",
      "owner_gid": "Alice"
    },
    "bundle_bin_base64": "...",
    "bundle_meta_base64": "..."
  }
}
```

Notes:
- this is the current practical API, not yet the final paper-perfect split of all MDO substeps.
- today the server returns the generated bundle package to the caller instead of automatically finalizing every later mobile-side step.

## CS mobile API

### `GET /mobile/state`

Purpose:
- retrieve current searchable state from CS
- inspect which bundle labels are currently stored

Example response:

```json
{
  "status": "ok",
  "blockchain_state": {
    "epoch": 1,
    "registration_root": "abc",
    "revocation_root": "def"
  },
  "stored_bundle_labels": ["demo1", "demo2"]
}
```

### `POST /mobile/query`

Purpose:
- submit an already prepared MDU query package to CS
- CS verifies auth, evaluates the search path, and returns matching bundles

Request:

```json
{
  "gid": "Alice",
  "preferred_label": "demo1",
  "auth_token_base64": "...",
  "shortlist_trapdoor_base64": "..."
}
```

Response:

```json
{
  "status": "ok",
  "stdout": "...",
  "stderr": "",
  "blockchain_state": {
    "epoch": 1,
    "registration_root": "abc",
    "revocation_root": "def"
  },
  "result": {
    "epoch": 1,
    "candidate_count": 2,
    "exact_match_count": 1,
    "bundles": [
      {
        "bundle_label": "demo1",
        "bundle_meta": {
          "bundle_label": "demo1"
        },
        "bundle_bin_base64": "...",
        "bundle_meta_base64": "..."
      }
    ]
  }
}
```

Notes:
- this endpoint expects query artifacts that are already prepared on the client side.
- in the final Android flow, trapdoor generation, proof preparation, and local decrypt/verify remain mobile responsibilities.

## Current responsibility split

Current backend state after this extension pass:

- TA / IA:
  - registration
  - credential issuance
  - state reporting
- Edge:
  - trusted encryption/bundle creation
  - state reporting
- CS:
  - query processing
  - result packaging
  - state reporting

Still expected on the Android side later:

- config and endpoint management
- local state persistence
- MDO local cryptographic preprocessing/finalization
- MDU trapdoor generation
- MDU ZKP packaging
- local verification and decryption of returned ciphertexts
- local epoch/query-state updates

## Current status

This document describes the current backend extension foundation. It is intended to stabilize Android development against a known HTTP contract. Further refinement is still expected as the real mobile app is implemented.
