param(
    [string]$NdkPath = "$env:LOCALAPPDATA\Android\Sdk\ndk\28.2.13676358",
    [string]$WorkDir = "$env:USERPROFILE\AndroidStudioProjects\abse-android-src",
    [ValidateSet("arm64-v8a", "x86_64")]
    [string]$Abi = "arm64-v8a",
    [string]$AndroidPlatform = "android-28",
    [string]$LiboqsSource = "",
    [string]$OpenfheSource = "",
    [switch]$SkipClone
)

$ErrorActionPreference = "Stop"

function Require-Command {
    param([string]$Name, [string]$Hint)
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Missing required command '$Name'. $Hint"
    }
}

function Convert-ToCMakePath {
    param([string]$Path)
    return (Resolve-Path $Path).Path.Replace("\", "/")
}

function New-Directory {
    param([string]$Path)
    New-Item -ItemType Directory -Force -Path $Path | Out-Null
}

function Apply-OpenfheAndroidPatch {
    param([string]$SourcePath)

    $callStackPath = Join-Path $SourcePath "src\core\lib\utils\get-call-stack.cpp"
    if (-not (Test-Path $callStackPath)) {
        Write-Host "OpenFHE call-stack source not found, skipping Android backtrace patch: $callStackPath" -ForegroundColor Yellow
        return
    }

    $content = Get-Content -Path $callStackPath -Raw
    $oldGuard = "#if defined(__linux__) && defined(__GNUC__)"
    $newGuard = "#if defined(__linux__) && defined(__GNUC__) && !defined(__ANDROID__)"

    if ($content.Contains($newGuard)) {
        Write-Host "OpenFHE Android backtrace patch already applied."
        return
    }

    if (-not $content.Contains($oldGuard)) {
        Write-Host "OpenFHE call-stack guard was not recognized, skipping Android backtrace patch." -ForegroundColor Yellow
        return
    }

    $content = $content.Replace($oldGuard, $newGuard)
    Set-Content -Path $callStackPath -Value $content -NoNewline
    Write-Host "Applied OpenFHE Android backtrace patch."
}

Require-Command cmake "Install CMake from Android Studio SDK Tools or https://cmake.org/download/."
Require-Command git "Install Git for Windows, or pass -SkipClone with existing source directories."

$ninja = Get-Command ninja -ErrorAction SilentlyContinue
if (-not $ninja) {
    $sdkNinja = Join-Path $env:LOCALAPPDATA "Android\Sdk\cmake"
    $ninjaCandidates = @()
    if (Test-Path $sdkNinja) {
        $ninjaCandidates = Get-ChildItem $sdkNinja -Recurse -Filter ninja.exe -ErrorAction SilentlyContinue | Select-Object -First 1
    }
    if ($ninjaCandidates) {
        $env:PATH = "$($ninjaCandidates.DirectoryName);$env:PATH"
    } else {
        throw "Missing required command 'ninja'. In Android Studio, install SDK Tools > CMake, or install Ninja and reopen PowerShell."
    }
}

if (-not (Test-Path $NdkPath)) {
    throw "NDK path does not exist: $NdkPath"
}

$toolchain = Join-Path $NdkPath "build\cmake\android.toolchain.cmake"
if (-not (Test-Path $toolchain)) {
    throw "Android CMake toolchain file not found: $toolchain"
}

New-Directory $WorkDir
$sourceRoot = Join-Path $WorkDir "src"
$buildRoot = Join-Path $WorkDir "build"
$prebuiltRoot = Join-Path $WorkDir "prebuilt"
$prebuiltAbi = Join-Path $prebuiltRoot $Abi
New-Directory $sourceRoot
New-Directory $buildRoot
New-Directory $prebuiltAbi

if ([string]::IsNullOrWhiteSpace($LiboqsSource)) {
    $LiboqsSource = Join-Path $sourceRoot "liboqs"
}
if ([string]::IsNullOrWhiteSpace($OpenfheSource)) {
    $OpenfheSource = Join-Path $sourceRoot "openfhe-development"
}

if (-not $SkipClone) {
    if (-not (Test-Path $LiboqsSource)) {
        git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git $LiboqsSource
    }
    if (-not (Test-Path $OpenfheSource)) {
        git clone --depth 1 https://github.com/openfheorg/openfhe-development.git $OpenfheSource
    }
}

if (-not (Test-Path $LiboqsSource)) {
    throw "liboqs source folder not found: $LiboqsSource"
}
if (-not (Test-Path $OpenfheSource)) {
    throw "OpenFHE source folder not found: $OpenfheSource"
}

Apply-OpenfheAndroidPatch $OpenfheSource

$toolchainCmake = Convert-ToCMakePath $toolchain
$prebuiltCmake = (New-Item -ItemType Directory -Force -Path $prebuiltAbi).FullName.Replace("\", "/")
$liboqsBuild = Join-Path $buildRoot "liboqs-$Abi"
$openfheBuild = Join-Path $buildRoot "openfhe-$Abi"

Write-Host ""
Write-Host "== Building liboqs for $Abi =="
cmake `
    -S $LiboqsSource `
    -B $liboqsBuild `
    -G Ninja `
    -DCMAKE_TOOLCHAIN_FILE="$toolchainCmake" `
    -DANDROID_ABI="$Abi" `
    -DANDROID_PLATFORM="$AndroidPlatform" `
    -DCMAKE_BUILD_TYPE=Release `
    -DCMAKE_INSTALL_PREFIX="$prebuiltCmake" `
    -DBUILD_SHARED_LIBS=OFF `
    -DOQS_BUILD_ONLY_LIB=ON `
    -DOQS_USE_OPENSSL=OFF `
    -DOQS_DIST_BUILD=ON
cmake --build $liboqsBuild --config Release --target install

Write-Host ""
Write-Host "== Building OpenFHE for $Abi =="
cmake `
    -S $OpenfheSource `
    -B $openfheBuild `
    -G Ninja `
    -DCMAKE_TOOLCHAIN_FILE="$toolchainCmake" `
    -DANDROID_ABI="$Abi" `
    -DANDROID_PLATFORM="$AndroidPlatform" `
    -DCMAKE_BUILD_TYPE=Release `
    -DCMAKE_INSTALL_PREFIX="$prebuiltCmake" `
    -DBUILD_SHARED=OFF `
    -DBUILD_STATIC=ON `
    -DBUILD_EXAMPLES=OFF `
    -DBUILD_UNITTESTS=OFF `
    -DBUILD_BENCHMARKS=OFF `
    -DWITH_OPENMP=OFF `
    -DWITH_NATIVEOPT=OFF
cmake --build $openfheBuild --config Release --target install

$libDir = Join-Path $prebuiltAbi "lib"
$includeDir = Join-Path $prebuiltAbi "include"

function Find-Library {
    param([string[]]$Names)
    foreach ($name in $Names) {
        $direct = Join-Path $libDir $name
        if (Test-Path $direct) {
            return $direct
        }
    }
    foreach ($name in $Names) {
        $found = Get-ChildItem $prebuiltAbi -Recurse -File -Filter $name -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($found) {
            return $found.FullName
        }
    }
    return $null
}

New-Directory $libDir

$normalizations = @(
    @{ Target = "libOPENFHEcore_static.a"; Names = @("libOPENFHEcore_static.a", "libOPENFHEcore.a") },
    @{ Target = "libOPENFHEpke_static.a"; Names = @("libOPENFHEpke_static.a", "libOPENFHEpke.a") },
    @{ Target = "libOPENFHEbinfhe_static.a"; Names = @("libOPENFHEbinfhe_static.a", "libOPENFHEbinfhe.a") }
)

foreach ($entry in $normalizations) {
    $target = Join-Path $libDir $entry.Target
    if (-not (Test-Path $target)) {
        $source = Find-Library $entry.Names
        if ($source) {
            Copy-Item $source $target -Force
        }
    }
}

$required = @(
    (Join-Path $includeDir "oqs"),
    (Join-Path $includeDir "openfhe"),
    (Join-Path $libDir "liboqs.a"),
    (Join-Path $libDir "libOPENFHEcore_static.a"),
    (Join-Path $libDir "libOPENFHEpke_static.a"),
    (Join-Path $libDir "libOPENFHEbinfhe_static.a")
)

$missing = @($required | Where-Object { -not (Test-Path $_) })
Write-Host ""
if ($missing.Count -gt 0) {
    Write-Host "Build finished, but the Android app is still missing expected files:" -ForegroundColor Yellow
    $missing | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
    Write-Host ""
    Write-Host "Send me the last CMake/build error output and this missing list; OpenFHE library names/options may need one adjustment for your source version." -ForegroundColor Yellow
    exit 2
}

Write-Host "Android prebuilts are ready:" -ForegroundColor Green
Write-Host "  $prebuiltAbi"
Write-Host ""
Write-Host "Use this for Android Studio/Gradle:"
Write-Host "  ABSE_ANDROID_PREBUILT_ROOT=$prebuiltRoot"
