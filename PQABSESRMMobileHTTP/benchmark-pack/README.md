# PQABSE Mobile Benchmark Pack

This pack runs Android-emulator benchmark jobs without changing the app's main UI or cloud workflow.

## What Runs

- Reference mobile primitive benchmarks: encryption, trapdoor generation, and decryption for the reference-paper baselines.
- Lightweight payload encryption benchmark: ChaCha20-Poly1305 only, excluding ABSE, secure-index construction, JNI native crypto, network, and cloud.
- Native fixture benchmarks: local encryption, trapdoor generation, and decryption through the Android JNI bridge when local fixture files are present.
- Native bridge status report, so you can quickly confirm whether the Panda4 emulator has the required native crypto prebuilts.

Native fixture encryption excludes HTTP/cloud upload and measures Android-side policy/header/session-key/secure-index construction for the requested keyword count.
Payload encryption mode measures only the paper's lightweight mobile payload encryption portion.
Fixture decryption first generates a retrieve trapdoor from the matched bundle, so it uses that bundle's `file_nonce` rather than the global shortlist nonce.

## Android Studio

1. Open `PQABSESRMMobileHTTP` in Android Studio Panda.
2. Start the Panda4 emulator.
3. Open `MobileBenchmarkPackInstrumentedTest`.
4. Run `runBenchmarkPack`.

Default output is written inside the app's external files directory under `benchmark-pack`.

## PowerShell

Use PowerShell from the Android Studio project root:

```powershell
cd C:\Users\User\AndroidStudioProjects\PQABSESRMMobileHTTP
$adb="$env:LOCALAPPDATA\Android\Sdk\platform-tools\adb.exe"
$pkg="com.example.pqabse_srmmobilehttp"
```

Set the native prebuilt root before Gradle builds that need the JNI crypto bridge:

```powershell
$env:ABSE_ANDROID_PREBUILT_ROOT="C:\Users\User\AndroidStudioProjects\abse-android-src\prebuilt"
```

Install the app and test APK:

```powershell
.\gradlew.bat :app:installDebug :app:installDebugAndroidTest
```

If native C++/JNI code changed, use `clean` once:

```powershell
.\gradlew.bat clean :app:installDebug :app:installDebugAndroidTest
```

The helper runner accepts the same instrumentation arguments and pulls CSVs with `adb exec-out cat | Out-File`:

```powershell
.\benchmark-pack\run_mobile_benchmarks.ps1 `
  -Mode payload `
  -KeywordCounts 10,50,300,500 `
  -Runs 30 `
  -WarmupRuns 30 `
  -PayloadBytes 4096
```

## Successful Payload-Only Mobile Encryption Run

This is the paper-aligned lightweight mobile encryption measurement. It measures only ChaCha20-Poly1305 payload encryption. It does not measure ABSE encapsulation, secure-index construction, trapdoor generation, decryption, network, cloud, or Edge/TEE work.

```powershell
& $adb shell am instrument -w `
  -e benchmarkMode payload `
  -e keywordCounts 10,50,300,500 `
  -e runs 30 `
  -e warmupRuns 30 `
  -e payloadBytes 4096 `
  -e class com.example.pqabse_srmmobilehttp.MobileBenchmarkPackInstrumentedTest#runBenchmarkPack `
  com.example.pqabse_srmmobilehttp.test/androidx.test.runner.AndroidJUnitRunner
```

Pull the payload CSVs with proper line breaks:

```powershell
New-Item -ItemType Directory -Force benchmark-pack\results\payload_mobile_primitives | Out-Null

& $adb exec-out cat /sdcard/Android/data/$pkg/files/benchmark-pack/payload_mobile_primitives/payload_mobile_primitives_raw.csv |
  Out-File -Encoding utf8 benchmark-pack\results\payload_mobile_primitives\payload_mobile_primitives_raw.csv

& $adb exec-out cat /sdcard/Android/data/$pkg/files/benchmark-pack/payload_mobile_primitives/payload_mobile_primitives_averages.csv |
  Out-File -Encoding utf8 benchmark-pack\results\payload_mobile_primitives\payload_mobile_primitives_averages.csv

Get-Content benchmark-pack\results\payload_mobile_primitives\payload_mobile_primitives_averages.csv
```

The result should be nearly flat across keyword counts. That is expected because payload encryption does not use keywords.

## Native Fixture Run Without Decryption

Use this when you want native local bundle construction and trapdoor timing but do not want to repeat the slow decryption benchmark:

```powershell
& $adb shell am instrument -w `
  -e benchmarkMode fixtures `
  -e includeDecryption false `
  -e keywordCounts 10,50,300,500 `
  -e runs 5 `
  -e class com.example.pqabse_srmmobilehttp.MobileBenchmarkPackInstrumentedTest#runBenchmarkPack `
  com.example.pqabse_srmmobilehttp.test/androidx.test.runner.AndroidJUnitRunner
```

Pull native fixture CSVs:

```powershell
New-Item -ItemType Directory -Force benchmark-pack\results\native_fixture_primitives | Out-Null

& $adb exec-out cat /sdcard/Android/data/$pkg/files/benchmark-pack/native_fixture_primitives/native_fixture_primitives_raw.csv |
  Out-File -Encoding utf8 benchmark-pack\results\native_fixture_primitives\native_fixture_primitives_raw.csv

& $adb exec-out cat /sdcard/Android/data/$pkg/files/benchmark-pack/native_fixture_primitives/native_fixture_primitives_averages.csv |
  Out-File -Encoding utf8 benchmark-pack\results\native_fixture_primitives\native_fixture_primitives_averages.csv

Get-Content benchmark-pack\results\native_fixture_primitives\native_fixture_primitives_averages.csv
```

## Fixture Mode

To run native encryption without cloud, place this file in `benchmark-pack/fixtures` or pass `-FixtureDir`:

- `phase1_params.txt`

To also run native trapdoor/decryption, add:

- `user_key.bin`
- `bundles/keywords_NNNN_bundle.bin` for each keyword count, for example `bundles/keywords_0010_bundle.bin`

You can generate matching mobile decrypt fixtures from the WSL repo:

```powershell
wsl.exe bash -lc "cd /home/user/PQABSE/Temp/PQABSE-SRM/PQABSESRMMobileHTTP && python3 benchmark-pack/generate_mobile_decrypt_fixtures.py"
```

By default, the generator writes fixtures into:

```text
PQABSESRMMobileHTTP\benchmark-pack\fixtures
```

Then push the fixture folder to the emulator before rerunning the benchmark.

```powershell
& $adb shell rm -rf /sdcard/Android/data/$pkg/files/benchmark-pack/fixtures
& $adb shell mkdir -p /sdcard/Android/data/$pkg/files/benchmark-pack
& $adb push benchmark-pack\fixtures /sdcard/Android/data/$pkg/files/benchmark-pack/
```

Fixture mode measures only Android-side JNI work. It does not contact TA, Edge, or CS.
For decryption runs, the Android test calls `generateRetrieveTrapdoorForBundle(...)`, which loads the bundle and serializes the trapdoor with the bundle's `file_nonce`.

## Native Android Prebuilts

The native fixture benchmark needs Android builds of liboqs and OpenFHE. If `native_status.txt` says the prebuilts are missing, build them from Windows PowerShell:

```powershell
.\benchmark-pack\build_android_prebuilts.ps1
```

The script defaults to:

```text
NDK: C:\Users\User\AppData\Local\Android\Sdk\ndk\28.2.13676358
Output: C:\Users\User\AndroidStudioProjects\abse-android-src\prebuilt\arm64-v8a
```

If it succeeds, set this environment variable before running Gradle/Android Studio builds that need the native crypto libraries:

```powershell
$env:ABSE_ANDROID_PREBUILT_ROOT="C:\Users\User\AndroidStudioProjects\abse-android-src\prebuilt"
```

The expected final files are:

```text
C:\Users\User\AndroidStudioProjects\abse-android-src\prebuilt\arm64-v8a\include
C:\Users\User\AndroidStudioProjects\abse-android-src\prebuilt\arm64-v8a\lib\liboqs.a
C:\Users\User\AndroidStudioProjects\abse-android-src\prebuilt\arm64-v8a\lib\libOPENFHEcore_static.a
C:\Users\User\AndroidStudioProjects\abse-android-src\prebuilt\arm64-v8a\lib\libOPENFHEpke_static.a
C:\Users\User\AndroidStudioProjects\abse-android-src\prebuilt\arm64-v8a\lib\libOPENFHEbinfhe_static.a
```

## Outputs

Benchmark output is written on the emulator under:

```text
/sdcard/Android/data/com.example.pqabse_srmmobilehttp/files/benchmark-pack
```

Pull files into:

```text
C:\Users\User\AndroidStudioProjects\PQABSESRMMobileHTTP\benchmark-pack\results
```

Expected files:

- `native_status.txt`
- `payload_mobile_primitives/payload_mobile_primitives_raw.csv`
- `payload_mobile_primitives/payload_mobile_primitives_averages.csv`
- `reference_mobile_primitives/reference_mobile_primitives_raw.csv`
- `reference_mobile_primitives/reference_mobile_primitives_averages.csv`
- `native_fixture_primitives/native_fixture_primitives_raw.csv`
- `native_fixture_primitives/native_fixture_primitives_averages.csv`

Always pull fresh results after each benchmark run. Reading old files from `benchmark-pack\results` is the easiest way to accidentally inspect stale data.

## Interpretation Notes

- `benchmarkMode payload` is the mobile lightweight encryption number: ChaCha20-Poly1305 payload encryption only.
- `benchmarkMode fixtures` with `includeDecryption=false` records native Android local bundle construction and trapdoor generation without repeating decryption.
- Native fixture `encryption` includes policy/header/session-key/secure-index construction, so it scales with keyword count.
- Payload-only encryption should not scale with keyword count. If the first keyword count is slower, rerun with warm-up or confirm that fresh results were pulled.
- The emulator may be x86_64 with translated `arm64-v8a`. For publication-quality absolute timing, rerun on a real ARM64 Android device when possible.
