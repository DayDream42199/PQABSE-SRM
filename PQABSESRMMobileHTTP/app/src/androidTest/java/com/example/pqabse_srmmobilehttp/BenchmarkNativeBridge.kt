package com.example.pqabse_srmmobilehttp

object BenchmarkNativeBridge {
    init {
        System.loadLibrary("pqabse_native_bridge")
    }

    external fun getBridgeStatus(): String

    external fun benchmarkNativeFixtureEncryption(
        phase1ParamsBytes: ByteArray,
        keywordsCsv: String,
        payloadBytes: Int
    ): String

    external fun generateShortlistTrapdoor(
        phase1ParamsBytes: ByteArray,
        userKeyBytes: ByteArray,
        preferredLabel: String,
        keywordsCsv: String
    ): String

    external fun generateRetrieveTrapdoorForBundle(
        phase1ParamsBytes: ByteArray,
        userKeyBytes: ByteArray,
        bundleBytes: ByteArray,
        preferredLabel: String,
        keywordsCsv: String
    ): String

    external fun decryptLatestQueryResult(
        phase1ParamsBytes: ByteArray,
        userKeyBytes: ByteArray,
        shortlistTrapdoorBytes: ByteArray,
        bundleBytes: ByteArray
    ): String
}
