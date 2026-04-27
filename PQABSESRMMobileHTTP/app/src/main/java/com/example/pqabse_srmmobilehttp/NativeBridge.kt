package com.example.pqabse_srmmobilehttp

object NativeBridge {
    init {
        System.loadLibrary("pqabse_native_bridge")
    }

    external fun getBridgeStatus(): String
    external fun generateShortlistTrapdoor(
        phase1ParamsBytes: ByteArray,
        userKeyBytes: ByteArray,
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
