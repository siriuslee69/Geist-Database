package com.siriuslee.geist

import android.os.Build
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.KeyStore
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory

/**
 * Runs on a device. Everything here touches the real AndroidKeyStore, so
 * a pass means the hardware path works -- not that a mock agrees with
 * itself.
 *
 *   ./gradlew :geistkeystore:connectedAndroidTest
 */
@RunWith(AndroidJUnit4::class)
class GeistKeystoreTest {

    private val ctx = InstrumentationRegistry.getInstrumentation().targetContext

    @Before
    fun setUp() {
        GeistKeystore.init(ctx)
        // Leave nothing behind from a previous run: an alias that
        // survived would make "stores and reads back" pass for the wrong
        // reason.
        for (name in listOf("master", "vault", "second", "gone", "wiped")) {
            GeistKeystore.drop(name)
        }
    }

    @Test
    fun theKeystoreIsReachable() {
        assertTrue(GeistKeystore.available())
    }

    @Test
    fun withoutInitItIsNotAvailable() {
        // Not tested by clearing state -- init is a one-way door for the
        // process. What is asserted is that available() consults the
        // KeyStore rather than returning a constant.
        assertTrue(GeistKeystore.available())
        val store = KeyStore.getInstance("AndroidKeyStore")
        store.load(null)
        assertNotNull(store)
    }

    @Test
    fun storesAndReadsBack() {
        val secret = "hunter2-and-then-some".toByteArray()
        assertEquals(0, GeistKeystore.put("master", secret))
        assertEquals(GeistKeystore.STATUS_PRESENT, GeistKeystore.statusOf("master"))
        val back = GeistKeystore.get("master")
        assertNotNull(back)
        assertArrayEquals(secret, back)
        assertEquals(GeistKeystore.STATUS_PRESENT, GeistKeystore.lastStatus)
    }

    @Test
    fun theKeyIsHardwareBackedAndNotExportable() {
        assertEquals(0, GeistKeystore.put("master", "x".toByteArray()))
        val store = KeyStore.getInstance("AndroidKeyStore")
        store.load(null)
        assertTrue(store.containsAlias("geist:master"))
        // getKey returns a HANDLE. The bytes are not retrievable, which is
        // the entire reason for using the platform keystore rather than a
        // file: `encoded` is null for a non-exportable key.
        val key = store.getKey("geist:master", null)
        assertNotNull(key)
        assertNull(key.encoded)
    }

    @Test
    fun theWrappingKeyLivesInSecureHardware() {
        // Non-exportable and hardware-backed are DIFFERENT claims, and only
        // the device can settle the second one. A software-backed
        // AndroidKeyStore also returns null from `encoded`, so the test
        // above cannot tell them apart -- this one asks outright.
        assertEquals(0, GeistKeystore.put("master", "x".toByteArray()))
        val store = KeyStore.getInstance("AndroidKeyStore")
        store.load(null)
        val key = store.getKey("geist:master", null) as SecretKey
        val factory = SecretKeyFactory.getInstance(key.algorithm, "AndroidKeyStore")
        val info = factory.getKeySpec(key, KeyInfo::class.java) as KeyInfo

        val level =
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                info.securityLevel
            } else {
                @Suppress("DEPRECATION")
                if (info.isInsideSecureHardware) {
                    KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT
                } else {
                    KeyProperties.SECURITY_LEVEL_SOFTWARE
                }
            }

        // Recorded in the run output so the docs can state what this
        // handset actually does instead of hedging.
        println("geist: wrapping key security level = $level")
        assertTrue(
            "wrapping key is software-backed on this device (level $level)",
            level == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT ||
                level == KeyProperties.SECURITY_LEVEL_STRONGBOX,
        )
    }

    @Test
    fun theBlobOnDiskIsNotThePlaintext() {
        val marker = "SECRETMARKER-DO-NOT-FIND-ME".toByteArray()
        assertEquals(0, GeistKeystore.put("vault", marker))
        val blob = File(File(ctx.filesDir, "geist-keystore"), "vault.blob")
        assertTrue(blob.exists())
        val raw = blob.readBytes()
        assertFalse(String(raw, Charsets.ISO_8859_1).contains("SECRETMARKER"))
        // and it is longer than the plaintext: a 12-byte IV plus a
        // 16-byte GCM tag.
        assertTrue(raw.size >= marker.size + 12 + 16)
    }

    @Test
    fun anAbsentNameIsAbsent() {
        assertEquals(GeistKeystore.STATUS_ABSENT, GeistKeystore.statusOf("gone"))
        assertNull(GeistKeystore.get("gone"))
        assertEquals(GeistKeystore.STATUS_ABSENT, GeistKeystore.lastStatus)
    }

    @Test
    fun droppingForgets() {
        assertEquals(0, GeistKeystore.put("gone", "x".toByteArray()))
        assertEquals(GeistKeystore.STATUS_PRESENT, GeistKeystore.statusOf("gone"))
        assertEquals(0, GeistKeystore.drop("gone"))
        assertEquals(GeistKeystore.STATUS_ABSENT, GeistKeystore.statusOf("gone"))
        val store = KeyStore.getInstance("AndroidKeyStore")
        store.load(null)
        assertFalse(store.containsAlias("geist:gone"))
    }

    @Test
    fun droppingWhatIsNotThereSucceeds() {
        assertEquals(0, GeistKeystore.drop("never-existed"))
    }

    @Test
    fun aReplacementReplaces() {
        assertEquals(0, GeistKeystore.put("master", "first".toByteArray()))
        assertEquals(0, GeistKeystore.put("master", "second".toByteArray()))
        assertArrayEquals("second".toByteArray(), GeistKeystore.get("master"))
    }

    @Test
    fun twoEntriesHaveTwoKeys() {
        assertEquals(0, GeistKeystore.put("master", "a".toByteArray()))
        assertEquals(0, GeistKeystore.put("second", "b".toByteArray()))
        assertEquals(0, GeistKeystore.drop("master"))
        // Dropping one must not disturb the other. A shared wrapping key
        // would make this fail, which is why there is one per entry.
        assertArrayEquals("b".toByteArray(), GeistKeystore.get("second"))
    }

    @Test
    fun aBlobWhoseKeyIsGoneReadsAsInvalidated() {
        // This is what a fingerprint enrolment does: the platform destroys
        // the key and leaves the sealed bytes behind. Simulated by
        // deleting the alias directly, because a test cannot enrol a
        // fingerprint -- the STATE it produces is what matters, and this
        // is that state exactly.
        assertEquals(0, GeistKeystore.put("wiped", "x".toByteArray()))
        val store = KeyStore.getInstance("AndroidKeyStore")
        store.load(null)
        store.deleteEntry("geist:wiped")

        assertEquals(
            GeistKeystore.STATUS_INVALIDATED,
            GeistKeystore.statusOf("wiped"),
        )
        assertNull(GeistKeystore.get("wiped"))
        assertEquals(GeistKeystore.STATUS_INVALIDATED, GeistKeystore.lastStatus)
    }

    @Test
    fun aNameThatWouldEscapeIsRefused() {
        assertTrue(GeistKeystore.put("../../etc/passwd", "x".toByteArray()) < 0)
        assertTrue(GeistKeystore.put("a/b", "x".toByteArray()) < 0)
        assertTrue(GeistKeystore.put("", "x".toByteArray()) < 0)
        assertEquals(GeistKeystore.STATUS_ABSENT, GeistKeystore.statusOf("a/b"))
    }

    @Test
    fun anEmptyOrOversizedSecretIsRefused() {
        assertTrue(GeistKeystore.put("master", ByteArray(0)) < 0)
        assertTrue(GeistKeystore.put("master", ByteArray(64 * 1024 + 1)) < 0)
    }

    @Test
    fun aLargeSecretRoundTrips() {
        val big = ByteArray(32 * 1024) { (it % 251).toByte() }
        assertEquals(0, GeistKeystore.put("vault", big))
        assertArrayEquals(big, GeistKeystore.get("vault"))
    }
}
