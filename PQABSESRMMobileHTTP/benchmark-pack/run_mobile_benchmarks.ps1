param(
    [ValidateSet("all", "reference", "payload", "fixtures")]
    [string]$Mode = "all",
    [string]$KeywordCounts = "10,50,300,500",
    [int]$Runs = 5,
    [int]$PayloadBytes = 4096,
    [int]$WarmupRuns = 30,
    [bool]$IncludeDecryption = $true,
    [string]$OutputSubdir = "benchmark-pack",
    [string]$FixtureDir = "",
    [string]$AdbPath = "$env:LOCALAPPDATA\Android\Sdk\platform-tools\adb.exe"
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectDir = Split-Path -Parent $scriptDir
$packageName = "com.example.pqabse_srmmobilehttp"
$runner = "androidx.test.runner.AndroidJUnitRunner"
$resultDir = Join-Path $scriptDir "results"
$resolvedFixtureDir = if ($FixtureDir) { $FixtureDir } else { Join-Path $scriptDir "fixtures" }

New-Item -ItemType Directory -Force -Path $resultDir | Out-Null

if (!(Test-Path $AdbPath)) {
    throw "adb not found at $AdbPath. Pass -AdbPath or install Android SDK platform-tools."
}

function Pull-DeviceFile {
    param(
        [string]$DevicePath,
        [string]$LocalPath
    )

    & $AdbPath shell "test -f '$DevicePath'"
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Device file not found: $DevicePath"
        return
    }

    $localDir = Split-Path -Parent $LocalPath
    New-Item -ItemType Directory -Force -Path $localDir | Out-Null
    & $AdbPath exec-out cat $DevicePath | Out-File -Encoding utf8 $LocalPath
}

Push-Location $projectDir
try {
    & $AdbPath wait-for-device

    cmd /c ".\gradlew.bat :app:installDebug :app:installDebugAndroidTest"
    if ($LASTEXITCODE -ne 0) {
        throw "Gradle build failed with exit code $LASTEXITCODE"
    }

    if (Test-Path $resolvedFixtureDir) {
        $deviceFixtureDir = "/sdcard/Android/data/$packageName/files/$OutputSubdir/fixtures"
        & $AdbPath shell "rm -rf '$deviceFixtureDir'"
        & $AdbPath shell "mkdir -p '$deviceFixtureDir'"
        & $AdbPath push (Join-Path $resolvedFixtureDir ".") $deviceFixtureDir
    }

    $instrumentPackage = "$packageName.test/$runner"
    $includeDecryptionText = $IncludeDecryption.ToString().ToLowerInvariant()
    & $AdbPath shell am instrument -w `
        -e class "com.example.pqabse_srmmobilehttp.MobileBenchmarkPackInstrumentedTest#runBenchmarkPack" `
        -e benchmarkMode $Mode `
        -e keywordCounts $KeywordCounts `
        -e runs $Runs `
        -e payloadBytes $PayloadBytes `
        -e warmupRuns $WarmupRuns `
        -e includeDecryption $includeDecryptionText `
        -e outputSubdir $OutputSubdir `
        $instrumentPackage

    $deviceRoot = "/sdcard/Android/data/$packageName/files/$OutputSubdir"
    Pull-DeviceFile "$deviceRoot/native_status.txt" (Join-Path $resultDir "native_status.txt")

    foreach ($suite in @("payload_mobile_primitives", "reference_mobile_primitives", "native_fixture_primitives")) {
        Pull-DeviceFile `
            "$deviceRoot/$suite/${suite}_raw.csv" `
            (Join-Path $resultDir "$suite\${suite}_raw.csv")
        Pull-DeviceFile `
            "$deviceRoot/$suite/${suite}_averages.csv" `
            (Join-Path $resultDir "$suite\${suite}_averages.csv")
    }

    Write-Host "Benchmark results: $resultDir"
}
finally {
    Pop-Location
}
