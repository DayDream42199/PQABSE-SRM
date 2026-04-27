package com.example.pqabse_srmmobilehttp

import android.annotation.SuppressLint
import android.content.Context
import android.webkit.JavascriptInterface
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.webkit.WebViewAssetLoader
import org.json.JSONObject
import java.util.UUID

class LocalZkProver(
    context: Context,
    private val webView: WebView
) {
    data class ProofArtifacts(
        val proofJson: String,
        val publicJson: String,
        val elapsedMs: Double
    )

    private val assetLoader = WebViewAssetLoader.Builder()
        .addPathHandler("/assets/", WebViewAssetLoader.AssetsPathHandler(context))
        .build()

    private val pendingCallbacks = mutableMapOf<String, (Result<ProofArtifacts>) -> Unit>()
    private val pendingScripts = ArrayDeque<String>()
    private var pageReady = false

    init {
        configureWebView()
    }

    @SuppressLint("SetJavaScriptEnabled")
    private fun configureWebView() {
        webView.settings.javaScriptEnabled = true
        webView.settings.domStorageEnabled = true
        webView.settings.allowFileAccess = false
        webView.settings.allowContentAccess = false
        webView.settings.javaScriptCanOpenWindowsAutomatically = false
        webView.addJavascriptInterface(ProverBridge(), "AndroidProver")
        webView.webViewClient = object : WebViewClient() {
            override fun shouldInterceptRequest(
                view: WebView?,
                request: WebResourceRequest
            ) = assetLoader.shouldInterceptRequest(request.url)

            override fun onPageFinished(view: WebView?, url: String?) {
                pageReady = true
                while (pendingScripts.isNotEmpty()) {
                    webView.evaluateJavascript(pendingScripts.removeFirst(), null)
                }
            }
        }
        webView.loadUrl("https://appassets.androidplatform.net/assets/zk/prover.html")
    }

    fun generateProof(inputJson: String, callback: (Result<ProofArtifacts>) -> Unit) {
        val requestId = UUID.randomUUID().toString()
        pendingCallbacks[requestId] = callback
        val payload = JSONObject().apply {
            put("requestId", requestId)
            put("inputJson", inputJson)
        }
        val script = "window.runProof(${JSONObject.quote(payload.toString())});"
        webView.post {
            if (pageReady) {
                webView.evaluateJavascript(script, null)
            } else {
                pendingScripts += script
            }
        }
    }

    fun destroy() {
        pendingCallbacks.clear()
        pendingScripts.clear()
        webView.removeJavascriptInterface("AndroidProver")
        webView.destroy()
    }

    private inner class ProverBridge {
        @JavascriptInterface
        fun onSuccess(resultJson: String) {
            val payload = JSONObject(resultJson)
            val requestId = payload.optString("requestId")
            val callback = pendingCallbacks.remove(requestId) ?: return
            val proofArtifacts = ProofArtifacts(
                proofJson = payload.getJSONObject("proof").toString(),
                publicJson = payload.getJSONArray("publicSignals").toString(),
                elapsedMs = payload.optDouble("elapsedMs", 0.0)
            )
            webView.post { callback(Result.success(proofArtifacts)) }
        }

        @JavascriptInterface
        fun onError(resultJson: String) {
            val payload = JSONObject(resultJson)
            val requestId = payload.optString("requestId")
            val callback = pendingCallbacks.remove(requestId) ?: return
            val message = payload.optString("message", "Unknown prover error")
            webView.post { callback(Result.failure(IllegalStateException(message))) }
        }
    }
}
