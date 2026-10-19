package com.siriuslee.geist.monitor

import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import org.json.JSONObject
import org.junit.Assert.assertTrue
import org.junit.Test

class DeviceCommandTest {
    // {.role: orchestrator, testKind: tkIntegration.}
    @Test fun commandThroughGeist() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val root = File(instrumentation.targetContext.filesDir, "monitor")
        val request = InstrumentationRegistry.getArguments().getString("request") ?: "{\"op\":\"status\"}"
        var answer = MonitorNative.request(root, request)
        assertTrue(answer, JSONObject(answer).optBoolean("ok"))
        val waitSeconds = (InstrumentationRegistry.getArguments().getString("waitSeconds")?.toInt() ?: 0).coerceIn(0, 60)
        repeat(waitSeconds) {
            Thread.sleep(1000)
            answer = MonitorNative.request(root, "{\"op\":\"status\"}")
        }
        File(root, "last-check.json").writeText(answer)
        assertTrue(answer, JSONObject(answer).optBoolean("ok"))
    }
}
