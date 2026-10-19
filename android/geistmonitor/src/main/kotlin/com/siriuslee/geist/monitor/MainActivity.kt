package com.siriuslee.geist.monitor

import android.app.Activity
import android.os.Bundle
import android.webkit.JavascriptInterface
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import java.io.File
import java.util.concurrent.Executors
import com.siriuslee.geist.GeistKeystore

object MonitorNative {
    init { System.loadLibrary("geist_monitor") }
    external fun call(root: ByteArray, request: ByteArray): ByteArray
    // {.role: orchestrator.}
    fun request(root: File, request: String): String =
        call(root.absolutePath.toByteArray(Charsets.UTF_8), request.toByteArray(Charsets.UTF_8)).toString(Charsets.UTF_8)
}

class MainActivity : Activity() {
    private lateinit var view: WebView
    private val worker = Executors.newSingleThreadExecutor()
    private val root: File get() = File(filesDir, "monitor")

    // {.role: orchestrator.}
    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        GeistKeystore.init(this)
        view = WebView(this)
        view.settings.javaScriptEnabled = true
        view.settings.allowFileAccess = false
        view.settings.allowContentAccess = false
        view.settings.blockNetworkLoads = true
        view.webViewClient = object : WebViewClient() {
            override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean = true
        }
        view.addJavascriptInterface(object {
            @JavascriptInterface
            fun request(request: String): String = MonitorNative.request(root, request)
        }, "GeistNative")
        setContentView(view)
        worker.execute {
            MonitorNative.request(root, "{\"op\":\"provision\"}")
            val html = MonitorNative.request(root, "{\"op\":\"page\"}")
            runOnUiThread { view.loadDataWithBaseURL("https://geist.local/", html, "text/html", "UTF-8", null) }
        }
    }

    // {.role: actor.}
    @Deprecated("Activity back navigation")
    override fun onBackPressed() {
        view.evaluateJavascript("document.getElementById('trace').classList.remove('open');document.activeElement.blur();", null)
    }
}
