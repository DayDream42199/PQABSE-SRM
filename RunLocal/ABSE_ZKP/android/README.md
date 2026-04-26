# Android Native Port Scaffold

This directory is the starting point for porting the local `ABSE_ZKP` query/decrypt stack to Android.

It does **not** make the Android app decrypt/query stack work yet.
Its purpose is to give the repo a concrete place for:

- Android NDK toolchain assumptions
- prebuilt-output layout for Android ABIs
- `liboqs` Android build scripts
- `OpenFHE` Android build scripts
- CMake integration references for future JNI work

## Why this exists

The local `ABSE_ZKP` implementation currently builds against Linux-hosted dependencies:

- `liboqs`
- `OpenFHE`

The current local CMake files expect headers and libraries under locations such as:

- `/usr/local/include/openfhe`
- `/usr/local/lib/libOPENFHEcore.so`
- `OQS::oqs`

That means the current native crypto stack cannot be dropped directly into the Android app.
We need Android-compatible builds of those dependencies first.

## Current target

The long-term Android-native goal is to expose local equivalents of:

- proof-backed auth-token generation
- shortlist trapdoor generation
- bundle retrieval/decrypt logic

The relevant local code path is:

- `pq_src/User.cpp`
- `pq_src/IdentityAuthority.cpp`
- `abse_src/phase4_search.cpp`
- `src/entities/SearchGateway.cpp`

## ABI output layout

Prebuilt Android outputs are expected under:

- `android/prebuilt/arm64-v8a`
- `android/prebuilt/armeabi-v7a`
- `android/prebuilt/x86_64`

Each ABI directory should eventually contain:

- `include/`
- `lib/`
- `cmake/`

Recommended future contents:

- `include/openfhe/...`
- `include/oqs/...`
- `lib/libOPENFHEcore.a` or `.so`
- `lib/liboqs.a` or `.so`

## Scripts

This scaffold provides two script entry points:

- `scripts/build_liboqs_android.sh`
- `scripts/build_openfhe_android.sh`

They are intentionally conservative:

- they do not download dependencies for you
- they expect local source trees for `liboqs` and `OpenFHE`
- they document the Android-NDK-oriented CMake shape we need

## Future app integration

The Android app JNI layer already exists in:

- `C:\Users\acer\Desktop\PQABSESRMMobileHTTP\app\src\main\cpp`

Once Android builds of `liboqs` and `OpenFHE` exist, the next app-side steps will be:

1. teach the app-native CMake to consume ABI-specific prebuilt outputs from this directory
2. vendor or mirror the required `ABSE_ZKP` sources into the JNI build
3. add real native wrappers for:
   - auth token generation
   - shortlist trapdoor generation
   - decrypt/search flow

## Reality check

This is a real native port effort.

Likely remaining work includes:

- resolving Android compatibility issues in `OpenFHE`
- choosing static vs shared linking for both crypto dependencies
- validating `liboqs` algorithm availability on Android, especially ML-DSA support
- trimming the native dependency surface to keep app builds manageable
- deciding how Android runtime state maps to the existing local file-based artifact layout
