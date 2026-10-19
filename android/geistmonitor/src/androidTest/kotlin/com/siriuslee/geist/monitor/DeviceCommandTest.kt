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
        val answer = MonitorNative.request(root, request)
        File(root, "last-check.json").writeText(answer)
        assertTrue(answer, JSONObject(answer).optBoolean("ok"))
    }
}
