package com.example.pqabse_srmmobilehttp

import android.os.Bundle
import android.os.SystemClock
import android.view.View
import android.webkit.WebView
import android.widget.Button
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import android.util.Base64
import com.google.android.material.textfield.TextInputEditText
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.BufferedReader
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.zip.GZIPInputStream
import java.util.zip.GZIPOutputStream

class MainActivity : AppCompatActivity() {
    private val ioExecutor = Executors.newSingleThreadExecutor()
    private var lastRegisterResponseBody: String? = null
    private var lastQueryResponseBody: String? = null
    private var lastUserKeyBase64: String? = null
    private var lastPhase1ParamsBase64: String? = null
    private var generatedAuthTokenBase64: String? = null
    private var generatedShortlistTrapdoorBase64: String? = null
    private var generatedProverStateBase64: String? = null
    private var generatedProofFileBase64: String? = null
    private var generatedPublicFileBase64: String? = null
    private var generatedVerificationKeyBase64: String? = null
    private var generatedRequestArchiveBase64: String? = null

    private data class HttpBinaryResponse(
        val statusCode: Int,
        val bodyBytes: ByteArray,
        val contentType: String
    )

    private data class MobileBenchmarkConfig(
        val taBaseUrl: String,
        val edgeBaseUrl: String,
        val csBaseUrl: String,
        val ownerGid: String,
        val searcherGid: String,
        val plaintext: String,
        val policyExpression: String,
        val preferredLabel: String,
        val sessionId: String
    )

    private data class MobileBenchmarkRun(
        val timestampUtc: String,
        val keywordCount: Int,
        val runIndex: Int,
        val ownerGid: String,
        val searcherGid: String,
        val bundleLabel: String,
        val encryptRoundtripMs: Double,
        val edgeEncryptBundleMs: Double?,
        val edgeBundleWriteMs: Double?,
        val edgeIndexUpdateMs: Double?,
        val localProveMs: Double,
        val mobileTrapdoorGenMs: Double,
        val submitQueryRoundtripMs: Double,
        val csSearchMs: Double?,
        val mobileDecryptMs: Double,
        val returnedBundles: Int,
        val decryptedBundles: Int
    )

    private lateinit var taUrlInput: TextInputEditText
    private lateinit var edgeUrlInput: TextInputEditText
    private lateinit var csUrlInput: TextInputEditText
    private lateinit var gidInput: TextInputEditText
    private lateinit var attributesInput: TextInputEditText
    private lateinit var bundleLabelInput: TextInputEditText
    private lateinit var plaintextInput: TextInputEditText
    private lateinit var keywordsInput: TextInputEditText
    private lateinit var policyAttrsInput: TextInputEditText
    private lateinit var revokeTargetInput: TextInputEditText
    private lateinit var refreshTargetInput: TextInputEditText
    private lateinit var preferredLabelInput: TextInputEditText
    private lateinit var queryGidInput: TextInputEditText
    private lateinit var queryKeywordsInput: TextInputEditText
    private lateinit var authTokenInput: TextInputEditText
    private lateinit var shortlistTrapdoorInput: TextInputEditText
    private lateinit var saveConfigButton: Button
    private lateinit var fetchStateButton: Button
    private lateinit var fetchEdgeStateButton: Button
    private lateinit var fetchCsStateButton: Button
    private lateinit var registerButton: Button
    private lateinit var revokeTargetButton: Button
    private lateinit var refreshUserButton: Button
    private lateinit var encryptButton: Button
    private lateinit var generateQueryArtifactsButton: Button
    private lateinit var submitQueryButton: Button
    private lateinit var decryptQueryResultButton: Button
    private lateinit var runMobileBenchmarksButton: Button
    private lateinit var showBenchmarkFilesButton: Button
    private lateinit var nativeStatusButton: Button
    private lateinit var showReturnedKeyButton: Button
    private lateinit var loadingIndicator: ProgressBar
    private lateinit var outputText: TextView
    private lateinit var proofWebView: WebView
    private lateinit var localZkProver: LocalZkProver

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContentView(R.layout.activity_main)
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main)) { v, insets ->
            val systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom)
            insets
        }

        taUrlInput = findViewById(R.id.taUrlInput)
        edgeUrlInput = findViewById(R.id.edgeUrlInput)
        csUrlInput = findViewById(R.id.csUrlInput)
        gidInput = findViewById(R.id.gidInput)
        attributesInput = findViewById(R.id.attributesInput)
        bundleLabelInput = findViewById(R.id.bundleLabelInput)
        plaintextInput = findViewById(R.id.plaintextInput)
        keywordsInput = findViewById(R.id.keywordsInput)
        policyAttrsInput = findViewById(R.id.policyAttrsInput)
        revokeTargetInput = findViewById(R.id.revokeTargetInput)
        refreshTargetInput = findViewById(R.id.refreshTargetInput)
        preferredLabelInput = findViewById(R.id.preferredLabelInput)
        queryGidInput = findViewById(R.id.queryGidInput)
        queryKeywordsInput = findViewById(R.id.queryKeywordsInput)
        authTokenInput = findViewById(R.id.authTokenInput)
        shortlistTrapdoorInput = findViewById(R.id.shortlistTrapdoorInput)
        saveConfigButton = findViewById(R.id.saveConfigButton)
        fetchStateButton = findViewById(R.id.fetchStateButton)
        fetchEdgeStateButton = findViewById(R.id.fetchEdgeStateButton)
        fetchCsStateButton = findViewById(R.id.fetchCsStateButton)
        registerButton = findViewById(R.id.registerButton)
        revokeTargetButton = findViewById(R.id.revokeTargetButton)
        refreshUserButton = findViewById(R.id.refreshUserButton)
        encryptButton = findViewById(R.id.encryptButton)
        generateQueryArtifactsButton = findViewById(R.id.generateQueryArtifactsButton)
        submitQueryButton = findViewById(R.id.submitQueryButton)
        decryptQueryResultButton = findViewById(R.id.decryptQueryResultButton)
        runMobileBenchmarksButton = findViewById(R.id.runMobileBenchmarksButton)
        showBenchmarkFilesButton = findViewById(R.id.showBenchmarkFilesButton)
        nativeStatusButton = findViewById(R.id.nativeStatusButton)
        showReturnedKeyButton = findViewById(R.id.showReturnedKeyButton)
        loadingIndicator = findViewById(R.id.loadingIndicator)
        outputText = findViewById(R.id.outputText)
        proofWebView = findViewById(R.id.proofWebView)
        localZkProver = LocalZkProver(this, proofWebView)

        loadSavedConfig()

        saveConfigButton.setOnClickListener {
            saveConfig()
            showToast("Configuration saved")
        }

        fetchStateButton.setOnClickListener {
            saveConfig()
            val taBaseUrl = taUrlInput.text?.toString()?.trim().orEmpty()
            if (taBaseUrl.isBlank()) {
                showToast("Enter a TA / IA URL first")
                return@setOnClickListener
            }
            runBackgroundRequest("TA State") {
                httpGetJson("${taBaseUrl.trimEnd('/')}/mobile/state")
            }
        }

        fetchEdgeStateButton.setOnClickListener {
            saveConfig()
            val edgeBaseUrl = edgeUrlInput.text?.toString()?.trim().orEmpty()
            if (edgeBaseUrl.isBlank()) {
                showToast("Enter an Edge URL first")
                return@setOnClickListener
            }
            runBackgroundRequest("Edge State") {
                httpGetJson("${edgeBaseUrl.trimEnd('/')}/mobile/state")
            }
        }

        fetchCsStateButton.setOnClickListener {
            saveConfig()
            val csBaseUrl = csUrlInput.text?.toString()?.trim().orEmpty()
            if (csBaseUrl.isBlank()) {
                showToast("Enter a CS URL first")
                return@setOnClickListener
            }
            runBackgroundRequest("CS State") {
                httpGetJson("${csBaseUrl.trimEnd('/')}/mobile/state")
            }
        }

        registerButton.setOnClickListener {
            saveConfig()
            val taBaseUrl = taUrlInput.text?.toString()?.trim().orEmpty()
            val gid = gidInput.text?.toString()?.trim().orEmpty()
            val attributes = parseCsv(attributesInput.text?.toString().orEmpty())
            if (taBaseUrl.isBlank()) {
                showToast("Enter a TA / IA URL first")
                return@setOnClickListener
            }
            if (gid.isBlank()) {
                showToast("Enter a user GID")
                return@setOnClickListener
            }
            if (attributes.isEmpty()) {
                showToast("Enter at least one attribute")
                return@setOnClickListener
            }
            runBackgroundRequest("Register User") {
                val payload = JSONObject().apply {
                    put("gid", gid)
                    put("attributes", JSONArray(attributes))
                }
                httpPostJson("${taBaseUrl.trimEnd('/')}/mobile/register", payload)
            }
        }

        revokeTargetButton.setOnClickListener {
            saveConfig()
            val taBaseUrl = taUrlInput.text?.toString()?.trim().orEmpty()
            val revokedGid = revokeTargetInput.text?.toString()?.trim().orEmpty()
            if (taBaseUrl.isBlank()) {
                showToast("Enter a TA / IA URL first")
                return@setOnClickListener
            }
            if (revokedGid.isBlank()) {
                showToast("Enter a revoke target GID")
                return@setOnClickListener
            }
            runBackgroundRequest("Revoke Target User") {
                val payload = JSONObject().apply {
                    put("revoked_gid", revokedGid)
                }
                httpPostJson("${taBaseUrl.trimEnd('/')}/mobile/revoke", payload)
            }
        }

        refreshUserButton.setOnClickListener {
            saveConfig()
            val taBaseUrl = taUrlInput.text?.toString()?.trim().orEmpty()
            val bootstrapGid = gidInput.text?.toString()?.trim().orEmpty()
            val gid = refreshTargetInput.text?.toString()?.trim().orEmpty().ifBlank { bootstrapGid }
            if (taBaseUrl.isBlank()) {
                showToast("Enter a TA / IA URL first")
                return@setOnClickListener
            }
            if (gid.isBlank()) {
                showToast("Enter a user GID to refresh")
                return@setOnClickListener
            }
            if (refreshTargetInput.text?.toString()?.trim().orEmpty().isBlank()) {
                refreshTargetInput.setText(gid)
            }
            runBackgroundRequest("Refresh Current User") {
                val payload = JSONObject().apply {
                    put("gid", gid)
                }
                httpPostJson("${taBaseUrl.trimEnd('/')}/mobile/refresh", payload)
            }
        }

        encryptButton.setOnClickListener {
            saveConfig()
            val edgeBaseUrl = edgeUrlInput.text?.toString()?.trim().orEmpty()
            val csBaseUrl = csUrlInput.text?.toString()?.trim().orEmpty()
            val ownerGid = gidInput.text?.toString()?.trim().orEmpty()
            val bundleLabel = bundleLabelInput.text?.toString()?.trim().orEmpty()
            val plaintext = plaintextInput.text?.toString()?.trim().orEmpty()
            val keywords = parseCsv(keywordsInput.text?.toString().orEmpty())
            val policyRaw = policyAttrsInput.text?.toString().orEmpty()
            if (edgeBaseUrl.isBlank()) {
                showToast("Enter an Edge URL first")
                return@setOnClickListener
            }
            if (ownerGid.isBlank()) {
                showToast("Enter an owner GID")
                return@setOnClickListener
            }
            if (bundleLabel.isBlank()) {
                showToast("Enter a bundle label")
                return@setOnClickListener
            }
            if (plaintext.isBlank()) {
                showToast("Enter plaintext to encrypt")
                return@setOnClickListener
            }
            if (keywords.isEmpty()) {
                showToast("Enter at least one keyword")
                return@setOnClickListener
            }
            val policyExpression = policyRaw.trim().takeIf(::looksLikeStructuredPolicyExpression)
            val policySpec = if (policyExpression == null) {
                try {
                    buildPolicySpec(policyRaw)
                } catch (exc: IllegalArgumentException) {
                    showToast(exc.message ?: "Invalid policy expression")
                    return@setOnClickListener
                }
            } else {
                null
            }
            setLoading(true)
            ioExecutor.execute {
                try {
                    val payload = JSONObject().apply {
                        put("owner_gid", ownerGid)
                        put("label", bundleLabel)
                        put("plaintext", plaintext)
                        put("keywords", JSONArray(keywords))
                        if (policyExpression != null) {
                            put("policy_expression", policyExpression)
                        } else {
                            put("policy_type", "threshold")
                            put("threshold", policySpec!!.threshold)
                            put("policy_attrs", JSONArray(policySpec.attributes))
                        }
                    }
                    val encryptResponse = httpPostJson("${edgeBaseUrl.trimEnd('/')}/mobile/encrypt", payload)
                    val importResponse = if (csBaseUrl.isNotBlank()) {
                        importBundleIntoCs(csBaseUrl, extractResponseBody(encryptResponse))
                    } else {
                        "CS import skipped: no CS URL configured"
                    }
                    runOnUiThread {
                        outputText.text = buildString {
                            appendLine("Encrypt Bundle")
                            appendLine(encryptResponse)
                            appendLine()
                            append(importResponse)
                        }.trimEnd()
                        setLoading(false)
                    }
                } catch (exc: Exception) {
                    runOnUiThread {
                        outputText.text = "Encrypt Bundle\nError: ${exc.message}"
                        setLoading(false)
                    }
                }
            }
        }


        generateQueryArtifactsButton.setOnClickListener {
            saveConfig()
            val taBaseUrl = taUrlInput.text?.toString()?.trim().orEmpty()
            val bootstrapGid = gidInput.text?.toString()?.trim().orEmpty()
            val gid = queryGidInput.text?.toString()?.trim().orEmpty().ifBlank { bootstrapGid }
            val preferredLabel = preferredLabelInput.text?.toString()?.trim().orEmpty()
            val keywords = parseCsv(queryKeywordsInput.text?.toString().orEmpty())
            if (taBaseUrl.isBlank()) {
                showToast("Enter a TA / IA URL first")
                return@setOnClickListener
            }
            if (gid.isBlank()) {
                showToast("Enter a user GID")
                return@setOnClickListener
            }
            if (queryGidInput.text?.toString()?.trim().orEmpty().isBlank()) {
                queryGidInput.setText(gid)
            }
            if (keywords.isEmpty()) {
                showToast("Enter query keywords first")
                return@setOnClickListener
            }

            setLoading(true)
            ioExecutor.execute {
                try {
                    val payload = JSONObject().apply {
                        put("gid", gid)
                        if (preferredLabel.isNotBlank()) {
                            put("preferred_label", preferredLabel)
                        }
                    }
                    val authResponseText = httpPostJson("${taBaseUrl.trimEnd('/')}/mobile/prepare-auth", payload)
                    val body = extractResponseBody(authResponseText)
                    val generated = JSONObject(body)
                    val authPackage = generated.optJSONObject("auth_package")
                    val authToken = authPackage?.optString("auth_token_base64").orEmpty()
                    val proverState = authPackage?.optString("prover_state_base64").orEmpty()
                    val inputFileBase64 = authPackage?.optString("input_file_base64").orEmpty()
                    val verificationKey = generated.optString("verification_key_base64").orEmpty()
                    val phase1Params = generated.optString("phase1_params_base64").orEmpty()

                    val effectivePhase1 = phase1Params.ifBlank { lastPhase1ParamsBase64 }
                        ?: throw IllegalStateException("Missing Phase 1 parameters from TA")
                    val effectiveUserKey = resolveCachedUserKey(gid)
                        ?: throw IllegalStateException("Register or refresh user $gid first so the app has a user key")
                    if (inputFileBase64.isBlank()) {
                        throw IllegalStateException("TA did not return prover input.json for local proving")
                    }
                    val inputJson = decodeBase64(inputFileBase64).toString(Charsets.UTF_8)

                    runOnUiThread {
                        localZkProver.generateProof(inputJson) { proveResult ->
                            proveResult.onFailure { error ->
                                outputText.text = "Generate Query Artifacts\nError: ${error.message}"
                                setLoading(false)
                            }
                            proveResult.onSuccess { proofArtifacts ->
                                ioExecutor.execute {
                                    try {
                                        val trapdoorResult = NativeBridge.generateShortlistTrapdoor(
                                            decodeBase64(effectivePhase1),
                                            decodeBase64(effectiveUserKey),
                                            preferredLabel,
                                            keywords.joinToString(",")
                                        )
                                        val trapdoorJson = JSONObject(trapdoorResult)
                                        if (trapdoorJson.optString("status") != "ok") {
                                            throw IllegalStateException(trapdoorResult)
                                        }
                                        val shortlistTrapdoor = trapdoorJson.optString("shortlist_trapdoor_base64")
                                        val proofFileBase64 = Base64.encodeToString(
                                            proofArtifacts.proofJson.toByteArray(Charsets.UTF_8),
                                            Base64.NO_WRAP
                                        )
                                        val publicFileBase64 = Base64.encodeToString(
                                            proofArtifacts.publicJson.toByteArray(Charsets.UTF_8),
                                            Base64.NO_WRAP
                                        )
                                        val requestArchive = Base64.encodeToString(
                                            buildQueryRequestArchive(
                                                decodeBase64(authToken),
                                                decodeBase64(shortlistTrapdoor),
                                                gid,
                                                preferredLabel,
                                                verificationKey.takeIf { it.isNotBlank() }?.let(::decodeBase64),
                                                proverState.takeIf { it.isNotBlank() }?.let(::decodeBase64),
                                                proofArtifacts.proofJson.toByteArray(Charsets.UTF_8),
                                                proofArtifacts.publicJson.toByteArray(Charsets.UTF_8)
                                            ),
                                            Base64.NO_WRAP
                                        )

                                        runOnUiThread {
                                            generatedAuthTokenBase64 = authToken.ifBlank { null }
                                            generatedShortlistTrapdoorBase64 = shortlistTrapdoor.ifBlank { null }
                                            generatedProverStateBase64 = proverState.ifBlank { null }
                                            generatedProofFileBase64 = proofFileBase64.ifBlank { null }
                                            generatedPublicFileBase64 = publicFileBase64.ifBlank { null }
                                            generatedVerificationKeyBase64 = verificationKey.ifBlank { null }
                                            generatedRequestArchiveBase64 = requestArchive.ifBlank { null }
                                            lastPhase1ParamsBase64 = phase1Params.ifBlank { lastPhase1ParamsBase64 }
                                            saveConfig()
                                            refreshGeneratedSecretPreviews()
                                            outputText.text = buildString {
                                                appendLine("Generate Query Artifacts")
                                                appendLine("HTTP 200")
                                                appendLine("status = ok")
                                                appendLine("gid = $gid")
                                                appendLine("auth_package = received")
                                                appendLine("verification_key = ${if (verificationKey.isNotBlank()) "received" else "missing"}")
                                                appendLine("phase1_params = ${if (phase1Params.isNotBlank()) "received" else "cached"}")
                                                appendLine("Local prove")
                                                appendLine("elapsed_ms = ${"%.3f".format(Locale.US, proofArtifacts.elapsedMs)}")
                                                appendLine("Trapdoor")
                                                appendLine("status = ${trapdoorJson.optString("status")}")
                                                append("shortlist_trapdoor = generated")
                                            }.trimEnd()
                                            setLoading(false)
                                        }
                                    } catch (exc: Exception) {
                                        runOnUiThread {
                                            outputText.text = "Generate Query Artifacts\nError: ${exc.message}"
                                            setLoading(false)
                                        }
                                    }
                                }
                            }
                        }
                    }
                } catch (exc: Exception) {
                    runOnUiThread {
                        outputText.text = "Generate Query Artifacts\nError: ${exc.message}"
                        setLoading(false)
                    }
                }
            }
        }

        submitQueryButton.setOnClickListener {
            saveConfig()
            val csBaseUrl = csUrlInput.text?.toString()?.trim().orEmpty()
            val bootstrapGid = gidInput.text?.toString()?.trim().orEmpty()
            val gid = queryGidInput.text?.toString()?.trim().orEmpty().ifBlank { bootstrapGid }
            val preferredLabel = preferredLabelInput.text?.toString()?.trim().orEmpty()
            val authTokenBase64 = resolveSecretValue(authTokenInput, generatedAuthTokenBase64)
            val shortlistTrapdoorBase64 = resolveSecretValue(shortlistTrapdoorInput, generatedShortlistTrapdoorBase64)
            if (csBaseUrl.isBlank()) {
                showToast("Enter a CS URL first")
                return@setOnClickListener
            }
            if (gid.isBlank()) {
                showToast("Enter a user GID")
                return@setOnClickListener
            }
            if (queryGidInput.text?.toString()?.trim().orEmpty().isBlank()) {
                queryGidInput.setText(gid)
            }
            if (authTokenBase64.isBlank()) {
                showToast("Enter auth token base64")
                return@setOnClickListener
            }
            if (shortlistTrapdoorBase64.isBlank()) {
                showToast("Enter shortlist trapdoor base64")
                return@setOnClickListener
            }
            setLoading(true)
            ioExecutor.execute {
                try {
                    val responseText = generatedRequestArchiveBase64?.takeIf { it.isNotBlank() }?.let { archive ->
                        val archiveResponse = httpPostArchive(
                            "${csBaseUrl.trimEnd('/')}/query/android-mobile",
                            decodeBase64(archive)
                        )
                        if (archiveResponse.statusCode in 200..299 &&
                            archiveResponse.contentType.lowercase(Locale.US).contains("gzip")
                        ) {
                            val queryJson = parseQueryArchiveResponse(archiveResponse.bodyBytes)
                            lastQueryResponseBody = queryJson
                            formatHttpResponse(archiveResponse.statusCode, queryJson)
                        } else {
                            val responseBody = archiveResponse.bodyBytes.toString(Charsets.UTF_8).ifBlank { "<empty response>" }
                            formatHttpResponse(archiveResponse.statusCode, responseBody)
                        }
                    } ?: run {
                        val payload = JSONObject().apply {
                            put("gid", gid)
                            if (preferredLabel.isNotBlank()) {
                                put("preferred_label", preferredLabel)
                            }
                            put("auth_token_base64", authTokenBase64)
                            put("shortlist_trapdoor_base64", shortlistTrapdoorBase64)
                            generatedProverStateBase64?.takeIf { it.isNotBlank() }?.let { put("prover_state_base64", it) }
                            generatedProofFileBase64?.takeIf { it.isNotBlank() }?.let { put("proof_file_base64", it) }
                            generatedPublicFileBase64?.takeIf { it.isNotBlank() }?.let { put("public_file_base64", it) }
                        }
                        val response = httpPostJson("${csBaseUrl.trimEnd('/')}/mobile/query", payload)
                        lastQueryResponseBody = extractResponseBody(response)
                        response
                    }
                    runOnUiThread {
                        outputText.text = "Submit Query\n$responseText"
                        setLoading(false)
                    }
                } catch (exc: Exception) {
                    runOnUiThread {
                        outputText.text = "Submit Query\nError: ${exc.message}"
                        setLoading(false)
                    }
                }
            }
        }

        decryptQueryResultButton.setOnClickListener {
            val queryResponseBody = lastQueryResponseBody.orEmpty()
            val shortlistTrapdoorBase64 = generatedShortlistTrapdoorBase64
            val activeQueryGid = queryGidInput.text?.toString()?.trim().orEmpty().ifBlank { gidInput.text?.toString()?.trim().orEmpty() }
            val userKeyBase64 = resolveCachedUserKey(activeQueryGid)
            val phase1ParamsBase64 = lastPhase1ParamsBase64
            if (queryResponseBody.isBlank()) {
                showToast("Submit a query first")
                return@setOnClickListener
            }
            if (shortlistTrapdoorBase64.isNullOrBlank()) {
                showToast("Generate query artifacts first")
                return@setOnClickListener
            }
            if (userKeyBase64.isNullOrBlank()) {
                showToast("Register a user first")
                return@setOnClickListener
            }
            if (phase1ParamsBase64.isNullOrBlank()) {
                showToast("Missing Phase 1 parameters from TA")
                return@setOnClickListener
            }

            try {
                val returnedBundles = extractReturnedBundles(queryResponseBody)
                val phase1ParamsBytes = decodeBase64(phase1ParamsBase64)
                val userKeyBytes = decodeBase64(userKeyBase64)
                val shortlistTrapdoorBytes = decodeBase64(shortlistTrapdoorBase64)
                val decryptedResults = returnedBundles.map { bundle ->
                    val nativeResult = NativeBridge.decryptLatestQueryResult(
                        phase1ParamsBytes,
                        userKeyBytes,
                        shortlistTrapdoorBytes,
                        decodeBase64(bundle.bundleBase64)
                    )
                    bundle to nativeResult
                }
                outputText.text = buildDecryptResultsOutput(decryptedResults)
            } catch (exc: Exception) {
                outputText.text = "Decrypt Query Result\nError: ${exc.message}"
            }
        }

        runMobileBenchmarksButton.setOnClickListener {
            saveConfig()
            runMobileKeywordBenchmarks()
        }

        showBenchmarkFilesButton.setOnClickListener {
            val benchmarkDir = benchmarkDirectory()
            outputText.text = buildString {
                appendLine("Mobile Benchmark Files")
                appendLine("directory = ${benchmarkDir.absolutePath}")
                appendLine("runs_csv = ${mobileBenchmarkRunsFile().absolutePath}")
                append("averages_csv = ${mobileBenchmarkAveragesFile().absolutePath}")
            }.trimEnd()
        }

        nativeStatusButton.setOnClickListener {
            outputText.text = "Native Bridge\n${NativeBridge.getBridgeStatus()}"
        }

        showReturnedKeyButton.setOnClickListener {
            val registerResponseBody = lastRegisterResponseBody
            if (registerResponseBody.isNullOrBlank()) {
                showToast("Register a user first")
                return@setOnClickListener
            }
            outputText.text = buildKeyOutput(registerResponseBody)
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        localZkProver.destroy()
        ioExecutor.shutdown()
    }

    private fun runMobileKeywordBenchmarks() {
        val config = try {
            buildMobileBenchmarkConfig()
        } catch (exc: IllegalArgumentException) {
            showToast(exc.message ?: "Invalid mobile benchmark configuration")
            return
        }

        setLoading(true)
        outputText.text = buildString {
            appendLine("Run Mobile Benchmarks")
            appendLine("keyword_counts = ${MOBILE_BENCHMARK_KEYWORD_COUNTS.joinToString(",")}")
            appendLine("repeats = $MOBILE_BENCHMARK_REPEATS")
            append("Preparing benchmark files...")
        }.trimEnd()

        ioExecutor.execute {
            try {
                val runsFile = mobileBenchmarkRunsFile()
                val averagesFile = mobileBenchmarkAveragesFile()
                ensureMobileBenchmarkHeaders(runsFile, averagesFile)
                val statusLines = mutableListOf<String>()
                val totalRuns = MOBILE_BENCHMARK_KEYWORD_COUNTS.size * MOBILE_BENCHMARK_REPEATS
                var completedRuns = 0

                MOBILE_BENCHMARK_KEYWORD_COUNTS.forEach { keywordCount ->
                    val groupRuns = mutableListOf<MobileBenchmarkRun>()
                    for (runIndex in 1..MOBILE_BENCHMARK_REPEATS) {
                        postMobileBenchmarkProgress(
                            keywordCount = keywordCount,
                            runIndex = runIndex,
                            completedRuns = completedRuns,
                            totalRuns = totalRuns,
                            statusLines = statusLines
                        )
                        val row = runSingleMobileBenchmark(config, keywordCount, runIndex)
                        appendMobileBenchmarkRun(runsFile, row)
                        groupRuns += row
                        completedRuns += 1
                    statusLines += buildString {
                        append("keywords=$keywordCount run=$runIndex/$MOBILE_BENCHMARK_REPEATS")
                        append(" encrypt_ms=${formatMs(row.encryptRoundtripMs)}")
                        append(" prove_ms=${formatMs(row.localProveMs)}")
                        append(" trapdoor_ms=${formatMs(row.mobileTrapdoorGenMs)}")
                        append(" decrypt_ms=${formatMs(row.mobileDecryptMs)}")
                        append(" per_bundle_ms=${formatNullableMs(row.decryptPerBundleMs())}")
                        append(" returned=${row.returnedBundles}")
                        append(" decrypted=${row.decryptedBundles}")
                    }
                }
                    appendMobileBenchmarkAverage(averagesFile, keywordCount, config, groupRuns)
                }

                runOnUiThread {
                    outputText.text = buildString {
                        appendLine("Run Mobile Benchmarks")
                        appendLine("status = ok")
                        appendLine("runs_csv = ${runsFile.absolutePath}")
                        appendLine("averages_csv = ${averagesFile.absolutePath}")
                        appendLine("completed_runs = $completedRuns")
                        if (statusLines.isNotEmpty()) {
                            appendLine()
                            statusLines.takeLast(8).forEach(::appendLine)
                        }
                    }.trimEnd()
                    setLoading(false)
                }
            } catch (exc: Exception) {
                runOnUiThread {
                    outputText.text = buildString {
                        appendLine("Run Mobile Benchmarks")
                        appendLine("status = error")
                        append("message = ${exc.message}")
                    }.trimEnd()
                    setLoading(false)
                }
            }
        }
    }

    private fun buildMobileBenchmarkConfig(): MobileBenchmarkConfig {
        val taBaseUrl = taUrlInput.text?.toString()?.trim().orEmpty()
        val edgeBaseUrl = edgeUrlInput.text?.toString()?.trim().orEmpty()
        val csBaseUrl = csUrlInput.text?.toString()?.trim().orEmpty()
        val ownerGid = gidInput.text?.toString()?.trim().orEmpty()
        val searcherGid = queryGidInput.text?.toString()?.trim().orEmpty().ifBlank { ownerGid }
        val plaintext = plaintextInput.text?.toString()?.trim().orEmpty().ifBlank { DEFAULT_BENCHMARK_PLAINTEXT }
        val preferredLabel = preferredLabelInput.text?.toString()?.trim().orEmpty()
        val policyRaw = policyAttrsInput.text?.toString().orEmpty().trim()
        if (taBaseUrl.isBlank()) throw IllegalArgumentException("Enter a TA / IA URL first")
        if (edgeBaseUrl.isBlank()) throw IllegalArgumentException("Enter an Edge URL first")
        if (csBaseUrl.isBlank()) throw IllegalArgumentException("Enter a CS URL first")
        if (ownerGid.isBlank()) throw IllegalArgumentException("Enter an owner GID first")
        if (searcherGid.isBlank()) throw IllegalArgumentException("Enter a searcher GID first")
        if (resolveCachedUserKey(searcherGid).isNullOrBlank()) {
            throw IllegalArgumentException("Register or refresh searcher $searcherGid first on this phone")
        }
        val policyExpression = when {
            policyRaw.isBlank() -> defaultPolicyExpressionForOwner()
            looksLikeStructuredPolicyExpression(policyRaw) -> policyRaw
            else -> buildPolicySpec(policyRaw).let { "${it.threshold}-of-${it.attributes.size}(${it.attributes.joinToString(",")})" }
        }
        return MobileBenchmarkConfig(
            taBaseUrl = taBaseUrl.trimEnd('/'),
            edgeBaseUrl = edgeBaseUrl.trimEnd('/'),
            csBaseUrl = csBaseUrl.trimEnd('/'),
            ownerGid = ownerGid,
            searcherGid = searcherGid,
            plaintext = plaintext,
            policyExpression = policyExpression,
            preferredLabel = preferredLabel,
            sessionId = System.currentTimeMillis().toString()
        )
    }

    private fun defaultPolicyExpressionForOwner(): String {
        val attributes = parseCsv(attributesInput.text?.toString().orEmpty())
        return if (attributes.isNotEmpty()) {
            "AND(${attributes.joinToString(",")})"
        } else {
            DEFAULT_BENCHMARK_POLICY_EXPRESSION
        }
    }

    private fun runSingleMobileBenchmark(
        config: MobileBenchmarkConfig,
        keywordCount: Int,
        runIndex: Int
    ): MobileBenchmarkRun {
        val bundleLabel = "bench_${config.sessionId}_${keywordCount}_${runIndex}"
        val benchmarkPreferredLabel = bundleLabel
        val keywords = generateBenchmarkKeywords(config.sessionId, keywordCount, runIndex)

        val encryptPayload = JSONObject().apply {
            put("owner_gid", config.ownerGid)
            put("label", bundleLabel)
            put("plaintext", config.plaintext)
            put("keywords", JSONArray(keywords))
            put("policy_expression", config.policyExpression)
        }
        val encryptStartNs = SystemClock.elapsedRealtimeNanos()
        val encryptResponse = httpPostJson("${config.edgeBaseUrl}/mobile/encrypt", encryptPayload)
        val encryptRoundtripMs = nanosToMillis(SystemClock.elapsedRealtimeNanos() - encryptStartNs)
        val encryptBody = extractResponseBody(encryptResponse)
        importBundleIntoCs(config.csBaseUrl, encryptBody)
        val encryptTimings = JSONObject(encryptBody).optJSONObject("timings")

        val authPayload = JSONObject().apply {
            put("gid", config.searcherGid)
            put("preferred_label", benchmarkPreferredLabel)
        }
        val authResponseText = httpPostJson("${config.taBaseUrl}/mobile/prepare-auth", authPayload)
        val generated = JSONObject(extractResponseBody(authResponseText))
        val authPackage = generated.optJSONObject("auth_package")
        val authToken = authPackage?.optString("auth_token_base64").orEmpty()
        val proverState = authPackage?.optString("prover_state_base64").orEmpty()
        val inputFileBase64 = authPackage?.optString("input_file_base64").orEmpty()
        val verificationKey = generated.optString("verification_key_base64").orEmpty()
        val phase1Params = generated.optString("phase1_params_base64").ifBlank { lastPhase1ParamsBase64 }
            ?: throw IllegalStateException("Missing Phase 1 parameters from TA")
        val effectiveUserKey = resolveCachedUserKey(config.searcherGid)
            ?: throw IllegalStateException("Missing cached user key for ${config.searcherGid}")
        if (inputFileBase64.isBlank()) {
            throw IllegalStateException("TA did not return prover input.json for local proving")
        }
        val inputJson = decodeBase64(inputFileBase64).toString(Charsets.UTF_8)
        val proofArtifacts = runLocalProofSync(inputJson)

        val trapdoorStartNs = SystemClock.elapsedRealtimeNanos()
        val trapdoorResult = NativeBridge.generateShortlistTrapdoor(
            decodeBase64(phase1Params),
            decodeBase64(effectiveUserKey),
            config.preferredLabel,
            keywords.joinToString(",")
        )
        val mobileTrapdoorGenMs = nanosToMillis(SystemClock.elapsedRealtimeNanos() - trapdoorStartNs)
        val trapdoorJson = JSONObject(trapdoorResult)
        if (trapdoorJson.optString("status") != "ok") {
            throw IllegalStateException(trapdoorResult)
        }
        val shortlistTrapdoor = trapdoorJson.optString("shortlist_trapdoor_base64")
        val proofFileBase64 = Base64.encodeToString(
            proofArtifacts.proofJson.toByteArray(Charsets.UTF_8),
            Base64.NO_WRAP
        )
        val publicFileBase64 = Base64.encodeToString(
            proofArtifacts.publicJson.toByteArray(Charsets.UTF_8),
            Base64.NO_WRAP
        )

        val requestArchive = Base64.encodeToString(
            buildQueryRequestArchive(
                decodeBase64(authToken),
                decodeBase64(shortlistTrapdoor),
                config.searcherGid,
                benchmarkPreferredLabel,
                verificationKey.takeIf { it.isNotBlank() }?.let(::decodeBase64),
                proverState.takeIf { it.isNotBlank() }?.let(::decodeBase64),
                proofArtifacts.proofJson.toByteArray(Charsets.UTF_8),
                proofArtifacts.publicJson.toByteArray(Charsets.UTF_8)
            ),
            Base64.NO_WRAP
        )

        val queryPayload = JSONObject().apply {
            put("gid", config.searcherGid)
            put("preferred_label", benchmarkPreferredLabel)
            put("request_id", "android-mobile-bench")
            put("request_archive_base64", requestArchive)
            put("auth_token_base64", authToken)
            put("shortlist_trapdoor_base64", shortlistTrapdoor)
            if (proverState.isNotBlank()) put("prover_state_base64", proverState)
            put("proof_file_base64", proofFileBase64)
            put("public_file_base64", publicFileBase64)
        }
        val submitStartNs = SystemClock.elapsedRealtimeNanos()
        val queryResponse = httpPostJson("${config.csBaseUrl}/mobile/query", queryPayload)
        val submitQueryRoundtripMs = nanosToMillis(SystemClock.elapsedRealtimeNanos() - submitStartNs)
        val queryBody = extractResponseBody(queryResponse)
        lastQueryResponseBody = queryBody
        val queryTimings = JSONObject(queryBody).optJSONObject("timings")
        val queryJson = JSONObject(queryBody)
        if (queryJson.optString("status") != "ok") {
            throw IllegalStateException(
                buildString {
                    appendLine("Benchmark query failed")
                    append(queryBody)
                }
            )
        }
        if (queryJson.optJSONObject("result")?.optJSONArray("bundles") == null) {
            throw IllegalStateException(
                buildString {
                    appendLine("Benchmark query did not return result.bundles")
                    append(queryBody)
                }
            )
        }

        val returnedBundles = extractReturnedBundles(queryBody)
        val phase1ParamsBytes = decodeBase64(phase1Params)
        val userKeyBytes = decodeBase64(effectiveUserKey)
        val shortlistTrapdoorBytes = decodeBase64(shortlistTrapdoor)
        val decryptStartNs = SystemClock.elapsedRealtimeNanos()
        val nativeResults = returnedBundles.map { bundle ->
            NativeBridge.decryptLatestQueryResult(
                phase1ParamsBytes,
                userKeyBytes,
                shortlistTrapdoorBytes,
                decodeBase64(bundle.bundleBase64)
            )
        }
        val mobileDecryptMs = nanosToMillis(SystemClock.elapsedRealtimeNanos() - decryptStartNs)
        val decryptedCount = nativeResults.count { result ->
            runCatching { JSONObject(result).optString("status") == "ok" }.getOrDefault(false)
        }

        return MobileBenchmarkRun(
            timestampUtc = timestampUtc(),
            keywordCount = keywordCount,
            runIndex = runIndex,
            ownerGid = config.ownerGid,
            searcherGid = config.searcherGid,
            bundleLabel = bundleLabel,
            encryptRoundtripMs = encryptRoundtripMs,
            edgeEncryptBundleMs = encryptTimings?.optDoubleOrNull("encrypt_bundle_ms"),
            edgeBundleWriteMs = encryptTimings?.optDoubleOrNull("bundle_write_ms"),
            edgeIndexUpdateMs = encryptTimings?.optDoubleOrNull("index_update_ms"),
            localProveMs = proofArtifacts.elapsedMs,
            mobileTrapdoorGenMs = mobileTrapdoorGenMs,
            submitQueryRoundtripMs = submitQueryRoundtripMs,
            csSearchMs = queryTimings?.optDoubleOrNull("candidate_generation_ms"),
            mobileDecryptMs = mobileDecryptMs,
            returnedBundles = returnedBundles.size,
            decryptedBundles = decryptedCount
        )
    }

    private fun runLocalProofSync(inputJson: String): LocalZkProver.ProofArtifacts {
        val latch = CountDownLatch(1)
        var artifacts: LocalZkProver.ProofArtifacts? = null
        var failure: Throwable? = null
        runOnUiThread {
            localZkProver.generateProof(inputJson) { result ->
                result
                    .onSuccess { artifacts = it }
                    .onFailure { failure = it }
                latch.countDown()
            }
        }
        if (!latch.await(5, TimeUnit.MINUTES)) {
            throw IllegalStateException("Local proof generation timed out")
        }
        failure?.let { throw IllegalStateException(it.message ?: "Local proof generation failed", it) }
        return artifacts ?: throw IllegalStateException("Local proof generation returned no artifacts")
    }

    private fun postMobileBenchmarkProgress(
        keywordCount: Int,
        runIndex: Int,
        completedRuns: Int,
        totalRuns: Int,
        statusLines: List<String>
    ) {
        runOnUiThread {
            outputText.text = buildString {
                appendLine("Run Mobile Benchmarks")
                appendLine("status = running")
                appendLine("keywords = $keywordCount")
                appendLine("run = $runIndex/$MOBILE_BENCHMARK_REPEATS")
                appendLine("overall = ${completedRuns + 1}/$totalRuns")
                if (statusLines.isNotEmpty()) {
                    appendLine()
                    statusLines.takeLast(6).forEach(::appendLine)
                }
            }.trimEnd()
        }
    }

    private fun benchmarkDirectory(): File {
        val baseDir = getExternalFilesDir(null)
            ?: throw IllegalStateException("External app files directory is unavailable")
        return File(baseDir, "benchmarks").apply { mkdirs() }
    }

    private fun mobileBenchmarkRunsFile(): File = File(benchmarkDirectory(), MOBILE_BENCHMARK_RUNS_FILE)

    private fun mobileBenchmarkAveragesFile(): File = File(benchmarkDirectory(), MOBILE_BENCHMARK_AVERAGES_FILE)

    private fun ensureMobileBenchmarkHeaders(runsFile: File, averagesFile: File) {
    appendCsvHeaderIfMissing(
        runsFile,
        "timestamp_utc,keyword_count,run_index,owner_gid,searcher_gid,bundle_label,mobile_encrypt_roundtrip_ms,edge_encrypt_bundle_ms,edge_bundle_write_ms,edge_index_update_ms,local_prove_ms,mobile_trapdoor_gen_ms,submit_query_roundtrip_ms,cs_search_ms,mobile_decrypt_ms,mobile_decrypt_per_bundle_ms,returned_bundles,decrypted_bundles"
    )
    appendCsvHeaderIfMissing(
        averagesFile,
        "timestamp_utc,keyword_count,repeats,owner_gid,searcher_gid,avg_mobile_encrypt_roundtrip_ms,avg_edge_encrypt_bundle_ms,avg_edge_bundle_write_ms,avg_edge_index_update_ms,avg_local_prove_ms,avg_mobile_trapdoor_gen_ms,avg_submit_query_roundtrip_ms,avg_cs_search_ms,avg_mobile_decrypt_ms,avg_mobile_decrypt_per_bundle_ms,avg_returned_bundles,avg_decrypted_bundles"
    )
}

    private fun appendMobileBenchmarkRun(file: File, row: MobileBenchmarkRun) {
        appendCsvRow(
            file,
            listOf(
                row.timestampUtc,
                row.keywordCount,
                row.runIndex,
                row.ownerGid,
                row.searcherGid,
                row.bundleLabel,
                formatMs(row.encryptRoundtripMs),
                formatNullableMs(row.edgeEncryptBundleMs),
                formatNullableMs(row.edgeBundleWriteMs),
                formatNullableMs(row.edgeIndexUpdateMs),
            formatMs(row.localProveMs),
            formatMs(row.mobileTrapdoorGenMs),
            formatMs(row.submitQueryRoundtripMs),
            formatNullableMs(row.csSearchMs),
            formatMs(row.mobileDecryptMs),
            formatNullableMs(row.decryptPerBundleMs()),
            row.returnedBundles,
            row.decryptedBundles
        )
    )
    }

    private fun appendMobileBenchmarkAverage(
        file: File,
        keywordCount: Int,
        config: MobileBenchmarkConfig,
        rows: List<MobileBenchmarkRun>
    ) {
        appendCsvRow(
            file,
            listOf(
                timestampUtc(),
                keywordCount,
                rows.size,
                config.ownerGid,
                config.searcherGid,
                formatMs(rows.map { it.encryptRoundtripMs }.average()),
                formatNullableMs(rows.mapNotNull { it.edgeEncryptBundleMs }.averageOrNull()),
                formatNullableMs(rows.mapNotNull { it.edgeBundleWriteMs }.averageOrNull()),
                formatNullableMs(rows.mapNotNull { it.edgeIndexUpdateMs }.averageOrNull()),
            formatMs(rows.map { it.localProveMs }.average()),
            formatMs(rows.map { it.mobileTrapdoorGenMs }.average()),
            formatMs(rows.map { it.submitQueryRoundtripMs }.average()),
            formatNullableMs(rows.mapNotNull { it.csSearchMs }.averageOrNull()),
            formatMs(rows.map { it.mobileDecryptMs }.average()),
            formatNullableMs(rows.mapNotNull { it.decryptPerBundleMs() }.averageOrNull()),
            formatMs(rows.map { it.returnedBundles.toDouble() }.average()),
            formatMs(rows.map { it.decryptedBundles.toDouble() }.average())
        )
    )
}

    private fun appendCsvHeaderIfMissing(file: File, header: String) {
        if (!file.exists() || file.length() == 0L) {
            file.parentFile?.mkdirs()
            file.appendText(header + "\n")
        }
    }

    private fun appendCsvRow(file: File, values: List<Any?>) {
        file.parentFile?.mkdirs()
        val row = values.joinToString(",") { csvEscape(it?.toString().orEmpty()) }
        file.appendText(row + "\n")
    }

    private fun csvEscape(value: String): String {
        val escaped = value.replace("\"", "\"\"")
        return if (escaped.any { it == ',' || it == '"' || it == '\n' || it == '\r' }) {
            "\"$escaped\""
        } else {
            escaped
        }
    }

    private fun generateBenchmarkKeywords(sessionId: String, keywordCount: Int, runIndex: Int): List<String> {
        return (1..keywordCount).map { index ->
            "kw_${sessionId}_${keywordCount}_${runIndex}_${index.toString().padStart(4, '0')}"
        }
    }

    private fun extractJsonTiming(responseBody: String, key: String): Double? {
        return runCatching {
            JSONObject(responseBody).optJSONObject("timings")?.optDoubleOrNull(key)
        }.getOrNull()
    }

    private fun formatMs(value: Double): String = String.format(Locale.US, "%.3f", value)

    private fun formatNullableMs(value: Double?): String = value?.let(::formatMs).orEmpty()

    private fun nanosToMillis(durationNs: Long): Double = durationNs / 1_000_000.0

    private fun timestampUtc(): String {
        return SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US).apply {
            timeZone = java.util.TimeZone.getTimeZone("UTC")
        }.format(Date())
    }

private fun List<Double>.averageOrNull(): Double? = if (isEmpty()) null else average()

private fun MobileBenchmarkRun.decryptPerBundleMs(): Double? {
    return if (returnedBundles > 0) mobileDecryptMs / returnedBundles else null
}

private fun JSONObject.optDoubleOrNull(key: String): Double? {
        if (!has(key)) return null
        val value = optDouble(key, Double.NaN)
        return if (value.isNaN()) null else value
    }

    private fun loadSavedConfig() {
        val prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE)
        taUrlInput.setText(prefs.getString(KEY_TA_URL, DEFAULT_TA_URL))
        edgeUrlInput.setText(prefs.getString(KEY_EDGE_URL, DEFAULT_EDGE_URL))
        csUrlInput.setText(prefs.getString(KEY_CS_URL, DEFAULT_CS_URL))
        gidInput.setText(prefs.getString(KEY_GID, ""))
        attributesInput.setText(prefs.getString(KEY_ATTRIBUTES, ""))
        bundleLabelInput.setText(prefs.getString(KEY_BUNDLE_LABEL, ""))
        plaintextInput.setText(prefs.getString(KEY_PLAINTEXT, ""))
        keywordsInput.setText(prefs.getString(KEY_KEYWORDS, ""))
        policyAttrsInput.setText(prefs.getString(KEY_POLICY_ATTRS, ""))
        revokeTargetInput.setText(prefs.getString(KEY_REVOKE_TARGET_GID, ""))
        refreshTargetInput.setText(
            prefs.getString(KEY_REFRESH_TARGET_GID, null)
                ?: prefs.getString(KEY_GID, "")
        )
        preferredLabelInput.setText(prefs.getString(KEY_PREFERRED_LABEL, ""))
        queryGidInput.setText(
            prefs.getString(KEY_QUERY_GID, null)
                ?: prefs.getString(KEY_GID, "")
        )
        queryKeywordsInput.setText(
            prefs.getString(KEY_QUERY_KEYWORDS, null)
                ?: prefs.getString(KEY_KEYWORDS, "")
        )
        generatedAuthTokenBase64 = prefs.getString(KEY_AUTH_TOKEN, "")?.trim().orEmpty().ifBlank { null }
        generatedShortlistTrapdoorBase64 = prefs.getString(KEY_SHORTLIST_TRAPDOOR, "")?.trim().orEmpty().ifBlank { null }
        generatedProverStateBase64 = prefs.getString(KEY_PROVER_STATE, "")?.trim().orEmpty().ifBlank { null }
        generatedProofFileBase64 = prefs.getString(KEY_PROOF_FILE, "")?.trim().orEmpty().ifBlank { null }
        generatedPublicFileBase64 = prefs.getString(KEY_PUBLIC_FILE, "")?.trim().orEmpty().ifBlank { null }
        generatedVerificationKeyBase64 = prefs.getString(KEY_VERIFICATION_KEY, "")?.trim().orEmpty().ifBlank { null }
        generatedRequestArchiveBase64 = prefs.getString(KEY_REQUEST_ARCHIVE, "")?.trim().orEmpty().ifBlank { null }
        lastUserKeyBase64 = prefs.getString(KEY_USER_KEY, "")?.trim().orEmpty().ifBlank { null }
        lastPhase1ParamsBase64 = prefs.getString(KEY_PHASE1_PARAMS, "")?.trim().orEmpty().ifBlank { null }
        refreshGeneratedSecretPreviews()
    }

    private fun saveConfig() {
        getSharedPreferences(PREFS_NAME, MODE_PRIVATE)
            .edit()
            .putString(KEY_TA_URL, taUrlInput.text?.toString()?.trim().orEmpty())
            .putString(KEY_EDGE_URL, edgeUrlInput.text?.toString()?.trim().orEmpty())
            .putString(KEY_CS_URL, csUrlInput.text?.toString()?.trim().orEmpty())
            .putString(KEY_GID, gidInput.text?.toString()?.trim().orEmpty())
            .putString(KEY_ATTRIBUTES, attributesInput.text?.toString()?.trim().orEmpty())
            .putString(KEY_BUNDLE_LABEL, bundleLabelInput.text?.toString()?.trim().orEmpty())
            .putString(KEY_PLAINTEXT, plaintextInput.text?.toString().orEmpty())
            .putString(KEY_KEYWORDS, keywordsInput.text?.toString()?.trim().orEmpty())
            .putString(KEY_POLICY_ATTRS, policyAttrsInput.text?.toString()?.trim().orEmpty())
            .putString(KEY_REVOKE_TARGET_GID, revokeTargetInput.text?.toString()?.trim().orEmpty())
            .putString(KEY_REFRESH_TARGET_GID, refreshTargetInput.text?.toString()?.trim().orEmpty())
            .putString(KEY_PREFERRED_LABEL, preferredLabelInput.text?.toString()?.trim().orEmpty())
            .putString(KEY_QUERY_GID, queryGidInput.text?.toString()?.trim().orEmpty())
            .putString(KEY_QUERY_KEYWORDS, queryKeywordsInput.text?.toString()?.trim().orEmpty())
            .putString(KEY_AUTH_TOKEN, resolveSecretValue(authTokenInput, generatedAuthTokenBase64))
            .putString(KEY_SHORTLIST_TRAPDOOR, resolveSecretValue(shortlistTrapdoorInput, generatedShortlistTrapdoorBase64))
            .putString(KEY_PROVER_STATE, generatedProverStateBase64.orEmpty())
            .putString(KEY_PROOF_FILE, generatedProofFileBase64.orEmpty())
            .putString(KEY_PUBLIC_FILE, generatedPublicFileBase64.orEmpty())
            .putString(KEY_VERIFICATION_KEY, generatedVerificationKeyBase64.orEmpty())
            .putString(KEY_REQUEST_ARCHIVE, generatedRequestArchiveBase64.orEmpty())
            .putString(KEY_USER_KEY, lastUserKeyBase64.orEmpty())
            .putString(KEY_PHASE1_PARAMS, lastPhase1ParamsBase64.orEmpty())
            .apply()
    }

    private fun runBackgroundRequest(label: String, action: () -> String) {
        setLoading(true)
        ioExecutor.execute {
            try {
                val responseText = action()
                runOnUiThread {
                    if (label == "Register User" || label == "Refresh Current User") {
                        lastRegisterResponseBody = extractResponseBody(responseText)
                        cacheRegisterArtifacts(lastRegisterResponseBody)
                    } else if (label == "Submit Query") {
                        lastQueryResponseBody = extractResponseBody(responseText)
                    }
                    outputText.text = "$label\n$responseText"
                    setLoading(false)
                }
            } catch (exc: Exception) {
                runOnUiThread {
                    outputText.text = "$label\nError: ${exc.message}"
                    setLoading(false)
                }
            }
        }
    }

    private fun setLoading(isLoading: Boolean) {
        loadingIndicator.visibility = if (isLoading) View.VISIBLE else View.GONE
        saveConfigButton.isEnabled = !isLoading
        fetchStateButton.isEnabled = !isLoading
        fetchEdgeStateButton.isEnabled = !isLoading
        fetchCsStateButton.isEnabled = !isLoading
        registerButton.isEnabled = !isLoading
        revokeTargetButton.isEnabled = !isLoading
        refreshUserButton.isEnabled = !isLoading
        encryptButton.isEnabled = !isLoading
        generateQueryArtifactsButton.isEnabled = !isLoading
        submitQueryButton.isEnabled = !isLoading
        decryptQueryResultButton.isEnabled = !isLoading
        runMobileBenchmarksButton.isEnabled = !isLoading
        showBenchmarkFilesButton.isEnabled = !isLoading
        nativeStatusButton.isEnabled = !isLoading
        showReturnedKeyButton.isEnabled = !isLoading
    }

    private fun httpGetJson(url: String): String {
        val connection = (URL(url).openConnection() as HttpURLConnection).apply {
            requestMethod = "GET"
            connectTimeout = NETWORK_TIMEOUT_MS
            readTimeout = NETWORK_TIMEOUT_MS
            setRequestProperty("Accept", "application/json")
        }
        return connection.useJsonResponse()
    }

    private fun httpPostJson(url: String, payload: JSONObject): String {
        val connection = (URL(url).openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            connectTimeout = NETWORK_TIMEOUT_MS
            readTimeout = NETWORK_TIMEOUT_MS
            doOutput = true
            setRequestProperty("Content-Type", "application/json")
            setRequestProperty("Accept", "application/json")
        }
        OutputStreamWriter(connection.outputStream, Charsets.UTF_8).use { writer ->
            writer.write(payload.toString(2))
        }
        return connection.useJsonResponse()
    }

    private fun httpPostArchive(url: String, payload: ByteArray): HttpBinaryResponse {
        val connection = (URL(url).openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            connectTimeout = NETWORK_TIMEOUT_MS
            readTimeout = NETWORK_TIMEOUT_MS
            doOutput = true
            setRequestProperty("Content-Type", "application/gzip")
            setRequestProperty("Accept", "application/gzip, application/json")
        }
        connection.outputStream.use { output ->
            output.write(payload)
        }
        val statusCode = connection.responseCode
        val contentType = connection.contentType.orEmpty()
        val bodyBytes = readBytes(if (statusCode in 200..299) connection.inputStream else connection.errorStream)
        connection.disconnect()
        return HttpBinaryResponse(statusCode, bodyBytes, contentType)
    }

    private fun HttpURLConnection.useJsonResponse(): String {
        val statusCode = responseCode
        val responseBody = readStream(if (statusCode in 200..299) inputStream else errorStream)
        disconnect()
        return buildString {
            appendLine("HTTP $statusCode")
            append(responseBody.ifBlank { "<empty response>" })
        }
    }

    private fun readStream(stream: InputStream?): String {
        if (stream == null) return ""
        return BufferedReader(InputStreamReader(stream)).use { reader ->
            reader.readText()
        }
    }

    private fun readBytes(stream: InputStream?): ByteArray {
        if (stream == null) return ByteArray(0)
        return stream.use { it.readBytes() }
    }

    private fun parseCsv(raw: String): List<String> {
        return raw.split(",")
            .map { it.trim() }
            .filter { it.isNotEmpty() }
    }

    private data class PolicySpec(
        val attributes: List<String>,
        val threshold: Int
    )

    private fun looksLikeStructuredPolicyExpression(raw: String): Boolean {
        val trimmed = raw.trim()
        return Regex("""^(AND|OR|\d+-of-\d+)\s*\(""", RegexOption.IGNORE_CASE).containsMatchIn(trimmed)
    }

    private fun buildPolicySpec(raw: String): PolicySpec {
        val trimmed = raw.trim()
        if (trimmed.isBlank()) {
            throw IllegalArgumentException("Enter a policy expression")
        }

        val andMatch = Regex("""^AND\((.*)\)$""", RegexOption.IGNORE_CASE).matchEntire(trimmed)
        if (andMatch != null) {
            val attributes = parseCsv(andMatch.groupValues[1])
            if (attributes.isEmpty()) {
                throw IllegalArgumentException("AND(...) needs at least one attribute")
            }
            return PolicySpec(attributes, attributes.size)
        }

        val orMatch = Regex("""^OR\((.*)\)$""", RegexOption.IGNORE_CASE).matchEntire(trimmed)
        if (orMatch != null) {
            val attributes = parseCsv(orMatch.groupValues[1])
            if (attributes.isEmpty()) {
                throw IllegalArgumentException("OR(...) needs at least one attribute")
            }
            return PolicySpec(attributes, 1)
        }

        val thresholdMatch = Regex("""^(\d+)-of-(\d+)\((.*)\)$""", RegexOption.IGNORE_CASE).matchEntire(trimmed)
        if (thresholdMatch != null) {
            val threshold = thresholdMatch.groupValues[1].toIntOrNull()
                ?: throw IllegalArgumentException("Invalid threshold expression")
            val expectedCount = thresholdMatch.groupValues[2].toIntOrNull()
                ?: throw IllegalArgumentException("Invalid threshold expression")
            val attributes = parseCsv(thresholdMatch.groupValues[3])
            if (attributes.isEmpty()) {
                throw IllegalArgumentException("k-of-n(...) needs at least one attribute")
            }
            if (attributes.size != expectedCount) {
                throw IllegalArgumentException("Expected ${expectedCount} attributes but found ${attributes.size}")
            }
            if (threshold !in 1..attributes.size) {
                throw IllegalArgumentException("Threshold must be between 1 and ${attributes.size}")
            }
            return PolicySpec(attributes, threshold)
        }
        throw IllegalArgumentException("Use AND(...), OR(...), or k-of-n(...) for policy")
    }

    private fun extractResponseBody(responseText: String): String {
        val newlineIndex = responseText.indexOf('\n')
        return if (newlineIndex >= 0) {
            responseText.substring(newlineIndex + 1).trim()
        } else {
            responseText.trim()
        }
    }

    private fun refreshGeneratedSecretPreviews() {
        authTokenInput.setText(generatedAuthTokenBase64?.let(::summarizeSecret).orEmpty())
        shortlistTrapdoorInput.setText(generatedShortlistTrapdoorBase64?.let(::summarizeSecret).orEmpty())
    }

    private fun cacheRegisterArtifacts(responseBody: String?) {
        if (responseBody.isNullOrBlank()) return
        try {
            val json = JSONObject(responseBody)
            val userJson = json.optJSONObject("user")
            val cachedGid = userJson?.optString("gid").orEmpty()
            val cachedUserKey = userJson?.optString("user_key_base64").orEmpty().ifBlank { null }
            lastUserKeyBase64 = cachedUserKey
            if (cachedGid.isNotBlank() && cachedUserKey != null) {
                getSharedPreferences(PREFS_NAME, MODE_PRIVATE)
                    .edit()
                    .putString(userKeyStorageKey(cachedGid), cachedUserKey)
                    .apply()
            }
            lastPhase1ParamsBase64 = json.optString("phase1_params_base64").orEmpty().ifBlank { lastPhase1ParamsBase64 }
            saveConfig()
        } catch (_: Exception) {
            // Keep the last successful cached values if this response is not parseable JSON.
        }
    }

    private fun userKeyStorageKey(gid: String): String = "${KEY_USER_KEY}_$gid"

    private fun resolveCachedUserKey(gid: String): String? {
        val trimmed = gid.trim()
        if (trimmed.isBlank()) return null
        val prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE)
        val cached = prefs.getString(userKeyStorageKey(trimmed), "")?.trim().orEmpty().ifBlank { null }
        if (cached != null) return cached
        val currentGid = gidInput.text?.toString()?.trim().orEmpty()
        return if (trimmed == currentGid) lastUserKeyBase64 else null
    }

    private data class ReturnedBundle(
        val label: String,
        val bundleBase64: String
    )

    private fun extractReturnedBundles(queryResponseBody: String): List<ReturnedBundle> {
        val json = JSONObject(queryResponseBody)
        val bundles = json.optJSONObject("result")?.optJSONArray("bundles")
            ?: throw IllegalStateException("No result.bundles in latest query response")
        if (bundles.length() == 0) {
            throw IllegalStateException("No bundles returned by CS")
        }
        return buildList {
            for (index in 0 until bundles.length()) {
                val bundleJson = bundles.optJSONObject(index)
                    ?: throw IllegalStateException("Bundle entry $index is not an object")
                val bundleBase64 = bundleJson.optString("bundle_bin_base64").takeIf { it.isNotBlank() }
                    ?: throw IllegalStateException("bundle_bin_base64 missing from bundle entry $index")
                add(
                    ReturnedBundle(
                        label = bundleJson.optString("bundle_label").ifBlank { "bundle_${index + 1}" },
                        bundleBase64 = bundleBase64
                    )
                )
            }
        }
    }

    private fun importBundleIntoCs(csBaseUrl: String, encryptResponseBody: String): String {
        val json = JSONObject(encryptResponseBody)
        val bundle = json.optJSONObject("bundle")
        ?: throw IllegalStateException(
            buildString {
                appendLine("Encrypt response did not include bundle data")
                append(encryptResponseBody)
            }
        )
        val payload = JSONObject().apply {
            put("bundle", bundle)
        }
        return "Import Bundle To CS\n" + httpPostJson("${csBaseUrl.trimEnd('/')}/mobile/import-bundle", payload)
    }

    private fun decodeBase64(value: String): ByteArray {
        return Base64.decode(value, Base64.DEFAULT)
    }

    private fun formatHttpResponse(statusCode: Int, body: String): String {
        return buildString {
            appendLine("HTTP $statusCode")
            append(body.ifBlank { "<empty response>" })
        }
    }

    private fun buildQueryRequestArchive(
        authTokenBytes: ByteArray,
        shortlistTrapdoorBytes: ByteArray,
        gid: String,
        preferredLabel: String,
        verificationKeyBytes: ByteArray?,
        proverStateBytes: ByteArray?,
        proofFileBytes: ByteArray?,
        publicFileBytes: ByteArray?
    ): ByteArray {
        val tarBytes = ByteArrayOutputStream()
        writeTarEntry(tarBytes, "auth_token.txt", authTokenBytes)
        writeTarEntry(tarBytes, "shortlist_trapdoor.bin", shortlistTrapdoorBytes)
        writeTarEntry(tarBytes, "gid.txt", gid.toByteArray(Charsets.UTF_8))
        writeTarEntry(tarBytes, "preferred_label.txt", preferredLabel.toByteArray(Charsets.UTF_8))
        if (proverStateBytes != null && proverStateBytes.isNotEmpty()) {
            writeTarEntry(tarBytes, "prover_state.json", proverStateBytes)
        }
        if (proofFileBytes != null && proofFileBytes.isNotEmpty()) {
            writeTarEntry(tarBytes, "proof.json", proofFileBytes)
        }
        if (publicFileBytes != null && publicFileBytes.isNotEmpty()) {
            writeTarEntry(tarBytes, "public.json", publicFileBytes)
        }
        if (verificationKeyBytes != null && verificationKeyBytes.isNotEmpty()) {
            writeTarEntry(tarBytes, "verification_key.json", verificationKeyBytes)
        }
        tarBytes.write(ByteArray(1024))
        val gzipBytes = ByteArrayOutputStream()
        GZIPOutputStream(gzipBytes).use { gzip ->
            gzip.write(tarBytes.toByteArray())
        }
        return gzipBytes.toByteArray()
    }

    private fun writeTarEntry(out: ByteArrayOutputStream, name: String, data: ByteArray) {
        val header = ByteArray(512)
        writeTarString(header, 0, 100, name)
        writeTarOctal(header, 100, 8, 420)
        writeTarOctal(header, 108, 8, 0)
        writeTarOctal(header, 116, 8, 0)
        writeTarOctal(header, 124, 12, data.size.toLong())
        writeTarOctal(header, 136, 12, System.currentTimeMillis() / 1000)
        for (index in 148 until 156) {
            header[index] = ' '.code.toByte()
        }
        header[156] = '0'.code.toByte()
        writeTarString(header, 257, 6, "ustar")
        writeTarString(header, 263, 2, "00")
        val checksum = header.sumOf { it.toUByte().toInt() }
        writeTarOctal(header, 148, 8, checksum.toLong())
        out.write(header)
        out.write(data)
        val padding = (512 - (data.size % 512)) % 512
        if (padding != 0) {
            out.write(ByteArray(padding))
        }
    }

    private fun writeTarString(buffer: ByteArray, offset: Int, length: Int, value: String) {
        val bytes = value.toByteArray(Charsets.UTF_8)
        val count = minOf(bytes.size, length)
        System.arraycopy(bytes, 0, buffer, offset, count)
    }

    private fun writeTarOctal(buffer: ByteArray, offset: Int, length: Int, value: Long) {
        val raw = java.lang.Long.toOctalString(value)
        val text = raw.padStart(length - 2, '0') + "\u0000 "
        writeTarString(buffer, offset, length, text)
    }

    private fun parseQueryArchiveResponse(archiveBytes: ByteArray): String {
        val entries = readTarEntriesFromGzip(archiveBytes)
        val bundles = JSONArray()
        entries.keys
            .filter { it.startsWith("bundles/") && it.endsWith("_bundle.bin") }
            .sorted()
            .forEach { bundlePath ->
                val label = File(bundlePath).name.removeSuffix("_bundle.bin")
                val metaPath = "bundles/${label}_bundle.meta"
                val metaBytes = entries[metaPath]
                bundles.put(
                    JSONObject().apply {
                        put("bundle_label", label)
                        put("bundle_meta", parseKeyValueText(metaBytes?.toString(Charsets.UTF_8).orEmpty()))
                        put("bundle_bin_base64", Base64.encodeToString(entries.getValue(bundlePath), Base64.NO_WRAP))
                        put(
                            "bundle_meta_base64",
                            metaBytes?.let { Base64.encodeToString(it, Base64.NO_WRAP) }.orEmpty()
                        )
                    }
                )
            }

        val resultJson = JSONObject().apply {
            put("epoch", parseIntEntry(entries["epoch.txt"]))
            put("candidate_count", parseIntEntry(entries["candidate_count.txt"]))
            put("exact_match_count", parseIntEntry(entries["exact_match_count.txt"]))
            put("bundles", bundles)
        }

        return JSONObject().apply {
            put("status", "ok")
            put("stdout", "CS archive response parsed on Android")
            put("stderr", "")
            put("result", resultJson)
        }.toString()
    }

    private fun parseIntEntry(bytes: ByteArray?): Int {
        return bytes?.toString(Charsets.UTF_8)?.trim()?.toIntOrNull() ?: 0
    }

    private fun parseKeyValueText(text: String): JSONObject {
        val json = JSONObject()
        text.lineSequence()
            .map { it.trim() }
            .filter { it.contains("=") }
            .forEach { line ->
                val separatorIndex = line.indexOf('=')
                val key = line.substring(0, separatorIndex).trim()
                val value = line.substring(separatorIndex + 1).trim()
                json.put(key, value)
            }
        return json
    }

    private fun readTarEntriesFromGzip(archiveBytes: ByteArray): Map<String, ByteArray> {
        val tarBytes = GZIPInputStream(archiveBytes.inputStream()).use { gzip ->
            gzip.readBytes()
        }
        val entries = linkedMapOf<String, ByteArray>()
        var offset = 0
        while (offset + 512 <= tarBytes.size) {
            val header = tarBytes.copyOfRange(offset, offset + 512)
            if (header.all { it.toInt() == 0 }) {
                break
            }
            val name = extractTarString(header, 0, 100)
            val size = extractTarOctal(header, 124, 12)
            val typeFlag = header[156].toInt().toChar()
            val dataStart = offset + 512
            if (dataStart + size > tarBytes.size) {
                throw IOException("Tar entry $name exceeds archive size")
            }
            if (name.isNotBlank() && (typeFlag == '\u0000' || typeFlag == '0')) {
                entries[name] = tarBytes.copyOfRange(dataStart, dataStart + size)
            }
            val paddedSize = ((size + 511) / 512) * 512
            offset = dataStart + paddedSize
        }
        return entries
    }

    private fun extractTarString(block: ByteArray, start: Int, length: Int): String {
        val end = (start until (start + length))
            .firstOrNull { block[it].toInt() == 0 }
            ?: (start + length)
        return block.copyOfRange(start, end).toString(Charsets.UTF_8).trim()
    }

    private fun extractTarOctal(block: ByteArray, start: Int, length: Int): Int {
        val raw = block.copyOfRange(start, start + length)
            .toString(Charsets.UTF_8)
            .replace("\u0000", "")
            .trim()
        return raw.ifBlank { "0" }.toInt(8)
    }

    private fun renderDecryptResult(nativeResult: String): String {
        return try {
            val json = JSONObject(nativeResult)
            if (json.optString("status") != "ok") {
                when (json.optString("status")) {
                    "error" -> "status = error\nmessage = ${json.optString("message")}"
                    else -> nativeResult
                }
            } else {
                val sessionKey = decodeBase64(json.getString("session_key_base64"))
                val nonce = decodeBase64(json.getString("nonce_base64"))
                val ciphertext = decodeBase64(json.getString("ciphertext_base64"))
                val authTag = decodeBase64(json.getString("auth_tag_base64"))
                val plaintext = decryptChacha20Poly1305(sessionKey, nonce, ciphertext, authTag)
                buildString {
                    appendLine("status = ok")
                    appendLine("bundle_label = ${json.optString("bundle_label")}")
                    appendLine("matched_keywords = ${json.optJSONArray("matched_keywords") ?: JSONArray()}")
                    append("plaintext = $plaintext")
                }
            }
        } catch (_: Exception) {
            nativeResult
        }
    }

    private fun buildDecryptResultsOutput(results: List<Pair<ReturnedBundle, String>>): String {
        val successes = results.filter { (_, nativeResult) ->
            runCatching { JSONObject(nativeResult).optString("status") == "ok" }.getOrDefault(false)
        }
        val failures = results.filterNot { (_, nativeResult) ->
            runCatching { JSONObject(nativeResult).optString("status") == "ok" }.getOrDefault(false)
        }
        return buildString {
            appendLine("Decrypt Query Result")
            appendLine("returned_bundles = ${results.size}")
            appendLine("decrypted = ${successes.size}")
            appendLine("skipped = ${failures.size}")

            successes.forEachIndexed { index, (bundle, nativeResult) ->
                appendLine()
                appendLine("[${index + 1}] ${bundle.label}")
                append(renderDecryptResult(nativeResult))
                if (index != successes.lastIndex || failures.isNotEmpty()) {
                    appendLine()
                }
            }

            if (failures.isNotEmpty()) {
                appendLine()
                appendLine("Skipped Bundles")
                failures.forEach { (bundle, nativeResult) ->
                    appendLine("${bundle.label}: ${renderDecryptResult(nativeResult).replace('\n', ' ')}")
                }
            }
        }.trimEnd()
    }

    private fun decryptChacha20Poly1305(
        sessionKey: ByteArray,
        nonce: ByteArray,
        ciphertext: ByteArray,
        authTag: ByteArray
    ): String {
        val cipher = Cipher.getInstance("ChaCha20-Poly1305")
        val keySpec = SecretKeySpec(sessionKey, "ChaCha20")
        val ivSpec = IvParameterSpec(nonce)
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec)
        val combined = ByteArray(ciphertext.size + authTag.size)
        System.arraycopy(ciphertext, 0, combined, 0, ciphertext.size)
        System.arraycopy(authTag, 0, combined, ciphertext.size, authTag.size)
        val plaintextBytes = cipher.doFinal(combined)
        return plaintextBytes.toString(Charsets.UTF_8)
    }

    private fun resolveSecretValue(input: TextInputEditText, generatedValue: String?): String {
        val currentText = input.text?.toString()?.trim().orEmpty()
        if (generatedValue.isNullOrBlank()) {
            return currentText
        }
        return if (currentText == summarizeSecret(generatedValue)) generatedValue else currentText
    }

    private fun summarizeSecret(value: String): String {
        if (value.length <= 48) return value
        return "len=${value.length}  ${value.take(18)}...${value.takeLast(12)}"
    }

    private fun buildKeyOutput(responseBody: String): String {
        return try {
            val json = JSONObject(responseBody)
            val keyLines = mutableListOf<String>()
            collectInterestingFields("", json, keyLines)
            if (keyLines.isEmpty()) {
                "Returned Key\nNo key-like fields found.\n\n$responseBody"
            } else {
                buildString {
                    appendLine("Returned Key")
                    keyLines.forEach { appendLine(it) }
                }.trimEnd()
            }
        } catch (_: Exception) {
            "Returned Key\n$responseBody"
        }
    }

    private fun collectInterestingFields(prefix: String, value: Any?, results: MutableList<String>) {
        when (value) {
            is JSONObject -> {
                val iterator = value.keys()
                while (iterator.hasNext()) {
                    val key = iterator.next()
                    val childPrefix = if (prefix.isBlank()) key else "$prefix.$key"
                    collectInterestingFields(childPrefix, value.opt(key), results)
                }
            }
            is JSONArray -> {
                for (index in 0 until value.length()) {
                    collectInterestingFields("$prefix[$index]", value.opt(index), results)
                }
            }
            JSONObject.NULL, null -> Unit
            else -> {
                if (looksLikeKeyField(prefix)) {
                    val renderedValue = if (value is String) summarizeSecret(value) else value.toString()
                    results += "$prefix = $renderedValue"
                }
            }
        }
    }

    private fun looksLikeKeyField(path: String): Boolean {
        val lowerPath = path.lowercase()
        return listOf("key", "secret", "bundle", "package", "token", "cipher").any {
            lowerPath.contains(it)
        }
    }

    private fun showToast(message: String) {
        Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
    }

    companion object {
        private const val PREFS_NAME = "pqabse_mobile_http"
        private const val KEY_TA_URL = "ta_url"
        private const val KEY_EDGE_URL = "edge_url"
        private const val KEY_CS_URL = "cs_url"
        private const val KEY_GID = "gid"
        private const val KEY_ATTRIBUTES = "attributes"
        private const val KEY_BUNDLE_LABEL = "bundle_label"
        private const val KEY_PLAINTEXT = "plaintext"
        private const val KEY_KEYWORDS = "keywords"
        private const val KEY_QUERY_KEYWORDS = "query_keywords"
        private const val KEY_POLICY_ATTRS = "policy_attrs"
        private const val KEY_REVOKE_TARGET_GID = "revoke_target_gid"
        private const val KEY_REFRESH_TARGET_GID = "refresh_target_gid"
        private const val KEY_PREFERRED_LABEL = "preferred_label"
        private const val KEY_QUERY_GID = "query_gid"
        private const val KEY_AUTH_TOKEN = "auth_token"
        private const val KEY_SHORTLIST_TRAPDOOR = "shortlist_trapdoor"
        private const val KEY_PROVER_STATE = "prover_state"
        private const val KEY_PROOF_FILE = "proof_file"
        private const val KEY_PUBLIC_FILE = "public_file"
        private const val KEY_VERIFICATION_KEY = "verification_key"
        private const val KEY_REQUEST_ARCHIVE = "request_archive"
        private const val KEY_USER_KEY = "user_key"
        private const val KEY_PHASE1_PARAMS = "phase1_params"

        private const val DEFAULT_TA_URL = "http://10.0.2.2:8081"
        private const val DEFAULT_EDGE_URL = "http://10.0.2.2:8082"
        private const val DEFAULT_CS_URL = "http://10.0.2.2:8083"
        private const val NETWORK_TIMEOUT_MS = 900_000
        private const val DEFAULT_BENCHMARK_PLAINTEXT = "mobile benchmark payload"
        private const val DEFAULT_BENCHMARK_POLICY_EXPRESSION = "AND(ai)"
        private const val MOBILE_BENCHMARK_REPEATS = 5
        private val MOBILE_BENCHMARK_KEYWORD_COUNTS = listOf(10, 50, 300, 500)
        private const val MOBILE_BENCHMARK_RUNS_FILE = "mobile_benchmark_runs.csv"
        private const val MOBILE_BENCHMARK_AVERAGES_FILE = "mobile_benchmark_results.csv"
    }
}











