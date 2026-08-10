package com.siriuslee.geist

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.UserNotAuthenticatedException
import java.io.File
import java.security.KeyStore
import java.security.UnrecoverableKeyException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * The companion `geist/keystore.nim` binds to, and the only place in the
 * stack that talks to Android's own KeyStore.
 *
 * ## What is actually in hardware
 *
 * AndroidKeyStore stores KEYS, not arbitrary blobs. So an entry is two
 * pieces:
 *
 * ```
 *   AndroidKeyStore              app-private files
 *   -----------------            ----------------------
 *   alias "geist:master"   --->  master.blob  = iv | ciphertext
 *   AES-256-GCM, non-                          sealed with that key
 *   exportable, hardware-
 *   backed where available
 * ```
 *
 * The WRAPPING key never leaves hardware and cannot be read by this
 * process or any other. The wrapped blob is worthless without it, and is
 * destroyed with it.
 *
 * ## The one mapping that matters
 *
 * When the device owner adds a fingerprint or changes the screen lock,
 * Android permanently destroys keys bound to those credentials.
 * `Cipher.init` then throws [KeyPermanentlyInvalidatedException].
 *
 * That is mapped to status **2** (`ksInvalidated`) and to a negative
 * return from [get], so the Nim side can tell a person *this has to be
 * set up again* rather than *wrong password*. Everything else in this
 * file exists to serve that distinction.
 *
 * ## Status codes
 *
 * These are the ordinals of `KeyStatus` in `geist/keystore.nim` and must
 * not be reordered independently of it:
 *
 * ```
 *   0  absent        never stored, or dropped
 *   1  present       there, and retrievable
 *   2  invalidated   there, and PERMANENTLY unreadable
 *   3  unavailable   locked, busy, or not initialised -- retry is sane
 * ```
 */
object GeistKeystore {

    const val STATUS_ABSENT = 0
    const val STATUS_PRESENT = 1
    const val STATUS_INVALIDATED = 2
    const val STATUS_UNAVAILABLE = 3

    private const val PROVIDER = "AndroidKeyStore"
    private const val ALIAS_PREFIX = "geist:"
    private const val BLOB_DIR = "geist-keystore"
    private const val BLOB_SUFFIX = ".blob"
    private const val GCM_TAG_BITS = 128
    private const val GCM_IV_BYTES = 12
    private const val MAX_SECRET_BYTES = 64 * 1024

    /**
     * Where wrapped blobs live. Null until [init] is called, which is why
     * [available] answers false until then: a keystore that wrote its
     * blobs to a guessed path would lose them on the next release.
     */
    @Volatile
    private var blobDir: File? = null

    /**
     * Whether entries require the user to have authenticated recently.
     * Off by default: a password manager wants its vault key bound to a
     * biometric, but a mail client that must sync in the background does
     * not, and a library that forced one policy on both would be wrong
     * for one of them.
     */
    @Volatile
    private var requireAuth: Boolean = false

    @Volatile
    private var authValiditySeconds: Int = 15

    /**
     * Call once, from the app, before anything else.
     *
     * @param context any context; only [Context.getFilesDir] is used and
     *   no reference to the context is kept.
     */
    @JvmStatic
    @JvmOverloads
    fun init(
        context: Context,
        requireUserAuthentication: Boolean = false,
        authenticationValiditySeconds: Int = 15,
    ) {
        val dir = File(context.filesDir, BLOB_DIR)
        dir.mkdirs()
        blobDir = dir
        requireAuth = requireUserAuthentication
        authValiditySeconds = authenticationValiditySeconds
    }

    /** Reachable from this process? False until [init]. */
    @JvmStatic
    fun available(): Boolean {
        if (blobDir == null) return false
        return try {
            KeyStore.getInstance(PROVIDER).load(null)
            true
        } catch (t: Throwable) {
            false
        }
    }

    /**
     * A name becomes both a KeyStore alias and a filename, so the same
     * rule `checkName` applies in Nim applies here. Checked on BOTH sides
     * on purpose: this one is reachable from Kotlin callers that never go
     * through Nim.
     */
    private fun legalName(name: String): Boolean {
        if (name.isEmpty() || name.length > 128) return false
        if (name.contains("..") || name.contains('/') || name.contains('\\')) {
            return false
        }
        return name.all { it.isLetterOrDigit() || it == '-' || it == '_' || it == '.' }
    }

    private fun aliasOf(name: String) = ALIAS_PREFIX + name

    private fun blobOf(name: String): File? {
        val dir = blobDir ?: return null
        return File(dir, name + BLOB_SUFFIX)
    }

    private fun keystore(): KeyStore =
        KeyStore.getInstance(PROVIDER).apply { load(null) }

    /**
     * The wrapping key for one entry, created on first use.
     *
     * One key per entry rather than one for everything: dropping an entry
     * must destroy its key, and a shared key would make dropping one
     * entry silently invalidate the rest.
     */
    private fun wrappingKey(name: String, create: Boolean): SecretKey? {
        val store = keystore()
        val alias = aliasOf(name)
        val existing = store.getKey(alias, null) as? SecretKey
        if (existing != null) return existing
        if (!create) return null
        val builder = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
        if (requireAuth) {
            builder.setUserAuthenticationRequired(true)
            @Suppress("DEPRECATION")
            builder.setUserAuthenticationValidityDurationSeconds(authValiditySeconds)
        }
        val generator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            PROVIDER,
        )
        generator.init(builder.build())
        return generator.generateKey()
    }

    /**
     * Store one secret. Returns 0 on success.
     *
     * A replacement destroys the previous wrapping key first, so the old
     * blob becomes unreadable at the moment it is replaced rather than
     * lingering as something a later bug could resurrect.
     */
    @JvmStatic
    fun put(name: String, value: ByteArray): Int {
        if (!legalName(name)) return -1
        if (value.isEmpty() || value.size > MAX_SECRET_BYTES) return -2
        val blob = blobOf(name) ?: return -3
        return try {
            keystore().deleteEntry(aliasOf(name))
            val key = wrappingKey(name, create = true) ?: return -4
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key)
            val sealed = cipher.doFinal(value)
            val out = ByteArray(cipher.iv.size + sealed.size)
            cipher.iv.copyInto(out, 0)
            sealed.copyInto(out, cipher.iv.size)
            val tmp = File(blob.parentFile, blob.name + ".new")
            tmp.writeBytes(out)
            if (!tmp.renameTo(blob)) {
                tmp.delete()
                return -5
            }
            0
        } catch (t: Throwable) {
            -6
        }
    }

    /**
     * Take a secret back.
     *
     * Returns the bytes, or null with [lastStatus] set. Kotlin callers
     * should use [statusOf] alongside; the JNI layer turns a null into a
     * negative status, which is the convention the Nim side reads.
     */
    @JvmStatic
    fun get(name: String): ByteArray? {
        lastStatus = STATUS_UNAVAILABLE
        if (!legalName(name)) {
            lastStatus = STATUS_ABSENT
            return null
        }
        val blob = blobOf(name)
        if (blob == null) {
            lastStatus = STATUS_UNAVAILABLE
            return null
        }
        if (!blob.exists()) {
            lastStatus = STATUS_ABSENT
            return null
        }
        return try {
            val key = wrappingKey(name, create = false)
            if (key == null) {
                // The blob is here and its key is not. Only one thing does
                // that: the platform destroyed the key.
                lastStatus = STATUS_INVALIDATED
                return null
            }
            val raw = blob.readBytes()
            if (raw.size <= GCM_IV_BYTES) {
                lastStatus = STATUS_INVALIDATED
                return null
            }
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(
                Cipher.DECRYPT_MODE,
                key,
                GCMParameterSpec(GCM_TAG_BITS, raw, 0, GCM_IV_BYTES),
            )
            val plain = cipher.doFinal(raw, GCM_IV_BYTES, raw.size - GCM_IV_BYTES)
            lastStatus = STATUS_PRESENT
            plain
        } catch (e: KeyPermanentlyInvalidatedException) {
            // THE mapping this class exists for.
            lastStatus = STATUS_INVALIDATED
            null
        } catch (e: UnrecoverableKeyException) {
            lastStatus = STATUS_INVALIDATED
            null
        } catch (e: UserNotAuthenticatedException) {
            lastStatus = STATUS_UNAVAILABLE
            null
        } catch (t: Throwable) {
            lastStatus = STATUS_UNAVAILABLE
            null
        }
    }

    /** The status of the last [get]. */
    @JvmStatic
    @Volatile
    var lastStatus: Int = STATUS_ABSENT
        private set

    /** Forget one secret. Dropping what is not there is a success. */
    @JvmStatic
    fun drop(name: String): Int {
        if (!legalName(name)) return -1
        return try {
            keystore().deleteEntry(aliasOf(name))
            blobOf(name)?.delete()
            0
        } catch (t: Throwable) {
            -2
        }
    }

    /**
     * What is known about an entry, without unsealing it.
     *
     * Cheap on purpose: a startup path deciding between an unlock screen
     * and a setup screen should not have to run a cipher to find out.
     */
    @JvmStatic
    fun statusOf(name: String): Int {
        if (!legalName(name)) return STATUS_ABSENT
        val blob = blobOf(name) ?: return STATUS_UNAVAILABLE
        val hasBlob = blob.exists()
        return try {
            val hasKey = keystore().containsAlias(aliasOf(name))
            when {
                !hasBlob && !hasKey -> STATUS_ABSENT
                hasBlob && hasKey -> STATUS_PRESENT
                // A blob with no key is the invalidation case: the
                // platform removed the key and left the sealed bytes.
                hasBlob -> STATUS_INVALIDATED
                // A key with no blob is a half-finished put. Nothing can
                // be read from it, and it is not "there".
                else -> STATUS_ABSENT
            }
        } catch (t: Throwable) {
            STATUS_UNAVAILABLE
        }
    }
}
