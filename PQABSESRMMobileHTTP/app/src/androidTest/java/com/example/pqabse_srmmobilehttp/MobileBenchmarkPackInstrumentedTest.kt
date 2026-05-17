package com.example.pqabse_srmmobilehttp

import android.util.Base64
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONObject
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.SecureRandom
import java.util.Locale
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.math.sqrt
import kotlin.system.measureNanoTime

@RunWith(AndroidJUnit4::class)
class MobileBenchmarkPackInstrumentedTest {
    private val random = SecureRandom()

    @Test
    fun runBenchmarkPack() {
        val args = InstrumentationRegistry.getArguments()
        val mode = args.getString("benchmarkMode", "all").lowercase(Locale.US)
        val keywordCounts = parseKeywordCounts(args.getString("keywordCounts", "10,50,300,500"))
        val runs = args.getString("runs", "5").toInt().coerceAtLeast(1)
        val warmupRuns = args.getString("warmupRuns", "30").toInt().coerceAtLeast(0)
        val payloadBytes = args.getString("payloadBytes", "4096").toInt().coerceAtLeast(1)
        val includeDecryption = args.getString("includeDecryption", "true").toBoolean()
        val outputSubdir = args.getString("outputSubdir", "benchmark-pack")

        val targetContext = InstrumentationRegistry.getInstrumentation().targetContext
        val outputRoot = File(targetContext.getExternalFilesDir(null), outputSubdir)
        outputRoot.mkdirs()
        val nativeStatus = if (mode == "all" || mode == "fixtures") {
            BenchmarkNativeBridge.getBridgeStatus()
        } else {
            "Native bridge not loaded for benchmarkMode=$mode"
        }
        File(outputRoot, "native_status.txt").writeText(nativeStatus + "\n")

        when (mode) {
            "all" -> {
                runReferenceBenchmarks(outputRoot, keywordCounts, runs, warmupRuns, payloadBytes)
                runPayloadBenchmarks(outputRoot, keywordCounts, runs, warmupRuns, payloadBytes)
                runNativeFixtureBenchmarks(outputRoot, keywordCounts, runs, payloadBytes, includeDecryption)
            }
            "reference" -> runReferenceBenchmarks(outputRoot, keywordCounts, runs, warmupRuns, payloadBytes)
            "payload" -> runPayloadBenchmarks(outputRoot, keywordCounts, runs, warmupRuns, payloadBytes)
            "fixtures" -> runNativeFixtureBenchmarks(outputRoot, keywordCounts, runs, payloadBytes, includeDecryption)
            else -> throw IllegalArgumentException("Unsupported benchmarkMode: $mode")
        }
    }

    private fun runPayloadBenchmarks(
        outputRoot: File,
        keywordCounts: List<Int>,
        runs: Int,
        warmupRuns: Int,
        payloadBytes: Int
    ) {
        val rows = mutableListOf<BenchmarkRow>()
        warmUpPayloadCipher(warmupRuns, payloadBytes)

        for (keywordCount in keywordCounts) {
            val samples = List(runs) { newPayloadMaterial(payloadBytes) }
            samples.forEachIndexed { index, material ->
                val cipher = Cipher.getInstance(CHACHA20_POLY1305)
                var status = "ok"
                var message = ""
                val elapsed = measureNanoTime {
                    try {
                        cipher.init(
                            Cipher.ENCRYPT_MODE,
                            SecretKeySpec(material.key, "ChaCha20"),
                            IvParameterSpec(material.nonce)
                        )
                        cipher.doFinal(material.payload)
                    } catch (exc: Exception) {
                        status = "error"
                        message = exc.message.orEmpty()
                    }
                }
                rows += BenchmarkRow(
                    suite = "payload_mobile_primitives",
                    primitive = "payload_chacha20_poly1305_encrypt",
                    keywordCount = keywordCount,
                    run = index + 1,
                    payloadBytes = payloadBytes,
                    durationNs = elapsed,
                    status = status,
                    message = message
                )
            }
        }

        writeBenchmarkCsvs(outputRoot, "payload_mobile_primitives", rows)
    }

    private fun runReferenceBenchmarks(
        outputRoot: File,
        keywordCounts: List<Int>,
        runs: Int,
        warmupRuns: Int,
        payloadBytes: Int
    ) {
        val rows = mutableListOf<BenchmarkRow>()
        warmUpPayloadCipher(warmupRuns, payloadBytes)

        for (keywordCount in keywordCounts) {
            val keywordsCsv = keywordsCsv(keywordCount)
            repeat(runs) { runIndex ->
                val material = newPayloadMaterial(payloadBytes)
                rows += measureReferenceEncrypt(keywordCount, runIndex + 1, payloadBytes, material)
                rows += measureReferenceTrapdoor(keywordCount, runIndex + 1, payloadBytes, keywordsCsv)
                rows += measureReferenceDecrypt(keywordCount, runIndex + 1, payloadBytes, material)
            }
        }

        writeBenchmarkCsvs(outputRoot, "reference_mobile_primitives", rows)
    }

    private fun runNativeFixtureBenchmarks(
        outputRoot: File,
        keywordCounts: List<Int>,
        runs: Int,
        payloadBytes: Int,
        includeDecryption: Boolean
    ) {
        val rows = mutableListOf<BenchmarkRow>()
        val fixturesDir = File(outputRoot, "fixtures")
        val phase1File = File(fixturesDir, "phase1_params.txt")
        val userKeyFile = File(fixturesDir, "user_key.bin")
        val phase1Bytes = phase1File.takeIf { it.isFile }?.readBytes()
        val userKeyBytes = userKeyFile.takeIf { it.isFile }?.readBytes()

        for (keywordCount in keywordCounts) {
            val keywordsCsv = keywordsCsv(keywordCount)
            val bundleFile = File(fixturesDir, "bundles/keywords_%04d_bundle.bin".format(Locale.US, keywordCount))
            val bundleBytes = bundleFile.takeIf { it.isFile }?.readBytes()

            repeat(runs) { runIndex ->
                val runNumber = runIndex + 1
                rows += if (phase1Bytes == null) {
                    missingFixtureRow("native_fixture_encrypt", keywordCount, runNumber, payloadBytes, phase1File)
                } else {
                    measureNativeJson(
                        "native_fixture_encrypt",
                        keywordCount,
                        runNumber,
                        payloadBytes
                    ) {
                        BenchmarkNativeBridge.benchmarkNativeFixtureEncryption(phase1Bytes, keywordsCsv, payloadBytes)
                    }
                }

                rows += if (phase1Bytes == null || userKeyBytes == null) {
                    missingFixtureRow(
                        "native_shortlist_trapdoor",
                        keywordCount,
                        runNumber,
                        payloadBytes,
                        if (phase1Bytes == null) phase1File else userKeyFile
                    )
                } else {
                    measureNativeJson(
                        "native_shortlist_trapdoor",
                        keywordCount,
                        runNumber,
                        payloadBytes
                    ) {
                        BenchmarkNativeBridge.generateShortlistTrapdoor(
                            phase1Bytes,
                            userKeyBytes,
                            "keywords_%04d_shortlist_%02d".format(Locale.US, keywordCount, runNumber),
                            keywordsCsv
                        )
                    }
                }

                if (includeDecryption) {
                    if (phase1Bytes == null || userKeyBytes == null || bundleBytes == null) {
                        val missing = when {
                            phase1Bytes == null -> phase1File
                            userKeyBytes == null -> userKeyFile
                            else -> bundleFile
                        }
                        rows += missingFixtureRow("native_retrieve_trapdoor", keywordCount, runNumber, payloadBytes, missing)
                        rows += missingFixtureRow("native_decrypt", keywordCount, runNumber, payloadBytes, missing)
                    } else {
                        var retrieveJson = ""
                        rows += measureNativeJson(
                            "native_retrieve_trapdoor",
                            keywordCount,
                            runNumber,
                            payloadBytes
                        ) {
                            BenchmarkNativeBridge.generateRetrieveTrapdoorForBundle(
                                phase1Bytes,
                                userKeyBytes,
                                bundleBytes,
                                "keywords_%04d_retrieve_%02d".format(Locale.US, keywordCount, runNumber),
                                keywordsCsv
                            ).also { retrieveJson = it }
                        }

                        val retrieveTrapdoor = base64Field(retrieveJson, "retrieve_trapdoor_base64")
                        rows += if (retrieveTrapdoor == null) {
                            BenchmarkRow(
                                suite = "native_fixture_primitives",
                                primitive = "native_decrypt",
                                keywordCount = keywordCount,
                                run = runNumber,
                                payloadBytes = payloadBytes,
                                durationNs = 0L,
                                status = "skipped",
                                message = "retrieve trapdoor was not available"
                            )
                        } else {
                            measureNativeJson(
                                "native_decrypt",
                                keywordCount,
                                runNumber,
                                payloadBytes
                            ) {
                                BenchmarkNativeBridge.decryptLatestQueryResult(
                                    phase1Bytes,
                                    userKeyBytes,
                                    retrieveTrapdoor,
                                    bundleBytes
                                )
                            }
                        }
                    }
                }
            }
        }

        writeBenchmarkCsvs(outputRoot, "native_fixture_primitives", rows)
    }

    private fun measureReferenceEncrypt(
        keywordCount: Int,
        run: Int,
        payloadBytes: Int,
        material: PayloadMaterial
    ): BenchmarkRow {
        var status = "ok"
        var message = ""
        val cipher = Cipher.getInstance(CHACHA20_POLY1305)
        val elapsed = measureNanoTime {
            try {
                cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(material.key, "ChaCha20"), IvParameterSpec(material.nonce))
                cipher.doFinal(material.payload)
            } catch (exc: Exception) {
                status = "error"
                message = exc.message.orEmpty()
            }
        }
        return BenchmarkRow("reference_mobile_primitives", "reference_encrypt_chacha20_poly1305", keywordCount, run, payloadBytes, elapsed, status, message)
    }

    private fun measureReferenceTrapdoor(
        keywordCount: Int,
        run: Int,
        payloadBytes: Int,
        keywordsCsv: String
    ): BenchmarkRow {
        val key = ByteArray(32).also(random::nextBytes)
        val payload = keywordsCsv.toByteArray(Charsets.UTF_8)
        var status = "ok"
        var message = ""
        val mac = Mac.getInstance("HmacSHA256")
        val elapsed = measureNanoTime {
            try {
                mac.init(SecretKeySpec(key, "HmacSHA256"))
                mac.doFinal(payload)
            } catch (exc: Exception) {
                status = "error"
                message = exc.message.orEmpty()
            }
        }
        return BenchmarkRow("reference_mobile_primitives", "reference_trapdoor_hmac_sha256", keywordCount, run, payloadBytes, elapsed, status, message)
    }

    private fun measureReferenceDecrypt(
        keywordCount: Int,
        run: Int,
        payloadBytes: Int,
        material: PayloadMaterial
    ): BenchmarkRow {
        val ciphertext = chacha20Poly1305Encrypt(material)
        var status = "ok"
        var message = ""
        val cipher = Cipher.getInstance(CHACHA20_POLY1305)
        val elapsed = measureNanoTime {
            try {
                cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(material.key, "ChaCha20"), IvParameterSpec(material.nonce))
                cipher.doFinal(ciphertext)
            } catch (exc: Exception) {
                status = "error"
                message = exc.message.orEmpty()
            }
        }
        return BenchmarkRow("reference_mobile_primitives", "reference_decrypt_chacha20_poly1305", keywordCount, run, payloadBytes, elapsed, status, message)
    }

    private fun measureNativeJson(
        primitive: String,
        keywordCount: Int,
        run: Int,
        payloadBytes: Int,
        block: () -> String
    ): BenchmarkRow {
        var json = ""
        var status = "ok"
        var message = ""
        val elapsed = measureNanoTime {
            try {
                json = block()
            } catch (exc: Exception) {
                status = "error"
                message = exc.message.orEmpty()
            }
        }
        if (status == "ok") {
            status = jsonStatus(json)
            message = jsonMessage(json)
        }
        return BenchmarkRow("native_fixture_primitives", primitive, keywordCount, run, payloadBytes, elapsed, status, message)
    }

    private fun missingFixtureRow(
        primitive: String,
        keywordCount: Int,
        run: Int,
        payloadBytes: Int,
        file: File
    ) = BenchmarkRow(
        suite = "native_fixture_primitives",
        primitive = primitive,
        keywordCount = keywordCount,
        run = run,
        payloadBytes = payloadBytes,
        durationNs = 0L,
        status = "missing_fixture",
        message = "missing ${file.path}"
    )

    private fun warmUpPayloadCipher(warmupRuns: Int, payloadBytes: Int) {
        repeat(warmupRuns) {
            chacha20Poly1305Encrypt(newPayloadMaterial(payloadBytes))
        }
    }

    private fun chacha20Poly1305Encrypt(material: PayloadMaterial): ByteArray {
        val cipher = Cipher.getInstance(CHACHA20_POLY1305)
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(material.key, "ChaCha20"), IvParameterSpec(material.nonce))
        return cipher.doFinal(material.payload)
    }

    private fun newPayloadMaterial(payloadBytes: Int): PayloadMaterial {
        val key = ByteArray(32).also(random::nextBytes)
        val nonce = ByteArray(12).also(random::nextBytes)
        val payload = ByteArray(payloadBytes).also(random::nextBytes)
        return PayloadMaterial(key, nonce, payload)
    }

    private fun writeBenchmarkCsvs(outputRoot: File, suite: String, rows: List<BenchmarkRow>) {
        val dir = File(outputRoot, suite)
        dir.mkdirs()
        val rawFile = File(dir, "${suite}_raw.csv")
        val averagesFile = File(dir, "${suite}_averages.csv")

        rawFile.writeText("suite,primitive,keyword_count,run,payload_bytes,duration_ms,status,message\n")
        rows.forEach { rawFile.appendText(it.toCsvLine()) }

        averagesFile.writeText("suite,primitive,keyword_count,total_runs,ok_runs,payload_bytes,avg_ms,min_ms,max_ms,stddev_ms,status\n")
        rows.groupBy { it.primitive to it.keywordCount }
            .toSortedMap(compareBy<Pair<String, Int>> { it.first }.thenBy { it.second })
            .forEach { (_, group) ->
                averagesFile.appendText(averageCsvLine(group))
            }
    }

    private fun averageCsvLine(rows: List<BenchmarkRow>): String {
        val okRows = rows.filter { it.status == "ok" }
        val payloadBytes = rows.firstOrNull()?.payloadBytes ?: 0
        if (okRows.isEmpty()) {
            val first = rows.first()
            return listOf(
                first.suite,
                first.primitive,
                first.keywordCount.toString(),
                rows.size.toString(),
                "0",
                payloadBytes.toString(),
                "",
                "",
                "",
                "",
                rows.groupingBy { it.status }.eachCount().entries.joinToString("|") { "${it.key}:${it.value}" }
            ).joinToCsvLine()
        }

        val values = okRows.map { it.durationMs }
        val avg = values.average()
        val min = values.minOrNull() ?: 0.0
        val max = values.maxOrNull() ?: 0.0
        val variance = values.map { (it - avg) * (it - avg) }.average()
        val stddev = sqrt(variance)
        val first = rows.first()
        return listOf(
            first.suite,
            first.primitive,
            first.keywordCount.toString(),
            rows.size.toString(),
            okRows.size.toString(),
            payloadBytes.toString(),
            "%.6f".format(Locale.US, avg),
            "%.6f".format(Locale.US, min),
            "%.6f".format(Locale.US, max),
            "%.6f".format(Locale.US, stddev),
            rows.groupingBy { it.status }.eachCount().entries.joinToString("|") { "${it.key}:${it.value}" }
        ).joinToCsvLine()
    }

    private fun parseKeywordCounts(raw: String): List<Int> =
        raw.split(",")
            .mapNotNull { it.trim().takeIf(String::isNotEmpty)?.toInt() }
            .ifEmpty { listOf(10, 50, 300, 500) }

    private fun keywordsCsv(count: Int): String =
        (1..count).joinToString(",") { "kw_%04d".format(Locale.US, it) }

    private fun jsonStatus(json: String): String =
        runCatching { JSONObject(json).optString("status", "unknown") }.getOrDefault("invalid_json")

    private fun jsonMessage(json: String): String =
        runCatching {
            val parsed = JSONObject(json)
            parsed.optString("message", parsed.optString("details", ""))
        }.getOrDefault(json.take(160))

    private fun base64Field(json: String, field: String): ByteArray? =
        runCatching {
            val value = JSONObject(json).optString(field, "")
            if (value.isEmpty()) null else Base64.decode(value, Base64.DEFAULT)
        }.getOrNull()

    private fun BenchmarkRow.toCsvLine(): String =
        listOf(
            suite,
            primitive,
            keywordCount.toString(),
            run.toString(),
            payloadBytes.toString(),
            "%.6f".format(Locale.US, durationMs),
            status,
            message
        ).joinToCsvLine()

    private fun List<String>.joinToCsvLine(): String = joinToString(",") { csvEscape(it) } + "\n"

    private fun csvEscape(value: String): String {
        val escaped = value.replace("\"", "\"\"").replace("\r", " ").replace("\n", " ")
        return if (escaped.any { it == ',' || it == '"' }) "\"$escaped\"" else escaped
    }

    private data class PayloadMaterial(
        val key: ByteArray,
        val nonce: ByteArray,
        val payload: ByteArray
    )

    private data class BenchmarkRow(
        val suite: String,
        val primitive: String,
        val keywordCount: Int,
        val run: Int,
        val payloadBytes: Int,
        val durationNs: Long,
        val status: String,
        val message: String
    ) {
        val durationMs: Double = durationNs / 1_000_000.0
    }

    private companion object {
        const val CHACHA20_POLY1305 = "ChaCha20-Poly1305/None/NoPadding"
    }
}
