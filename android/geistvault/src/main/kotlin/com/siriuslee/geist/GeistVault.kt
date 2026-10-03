package com.siriuslee.geist

import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * Keyrings on Android: several sealed Geist stores in one folder, each
 * opened with its own password (see `src/geist/keyring.nim`).
 *
 * ```
 *   val v = GeistVault.create(dir, listOf("stage1", "stage2"), listOf("pw1", "pw1|pw2"))
 *   v.replace("stage1", listOf(GeistRingRow("card-1", "accounts", "{...}")))
 *   v.save(); v.close()
 *
 *   val w = GeistVault.open(dir)          // every ring locked
 *   w.unlock("stage1", "pw1")              // true; stage2 stays locked
 *   w.rows("stage1")
 * ```
 *
 * A ring that is never unlocked is never read or written, so a save made
 * with only some passwords leaves the other rings exactly as they were.
 *
 * Calls block on file IO and Argon2id (each unlock and each changed ring's
 * save derives a key): keep them off the main thread.
 */
class GeistVault private constructor(private val handle: Int, val rings: List<String>) : AutoCloseable {
    private var closed = false

    companion object {
        // {.role: orchestrator.}
        fun create(root: File, rings: List<String>, passwords: List<String>): GeistVault {
            val answer = GeistVaultNative.request(JSONObject().put("op", "create").put("root", root.path)
                .put("rings", JSONArray(rings)).put("passwords", JSONArray(passwords)))
            return GeistVault(answer.getInt("handle"), names(answer))
        }
        // {.role: orchestrator.}
        fun open(root: File): GeistVault {
            val answer = GeistVaultNative.request(JSONObject().put("op", "open").put("root", root.path))
            return GeistVault(answer.getInt("handle"), names(answer))
        }
        // {.role: parser.}
        // True when root holds a keyring set; reads only its public ring list.
        fun exists(root: File): Boolean = File(root, "rings").isFile
        // {.role: parser.}
        private fun names(answer: JSONObject): List<String> {
            val a = answer.getJSONArray("rings")
            return List(a.length()) { a.getString(it) }
        }
    }

    // {.role: decryptor.}
    // False for a wrong password; throws for anything else (a damaged ring, a full disk).
    fun unlock(ring: String, password: String): Boolean = try {
        call("unlock", ring) { put("password", password) }; true
    } catch (e: GeistVaultException) {
        if (e.code == GeistVaultException.WRONG_PASSWORD) false else throw e
    }
    // {.role: parser.}
    fun rows(ring: String): List<GeistRingRow> {
        val a = call("rows", ring).getJSONArray("rows")
        return List(a.length()) { i -> a.getJSONObject(i).let { GeistRingRow(it.getString("rowKey"), it.getString("kind"), it.getString("body")) } }
    }
    // {.role: actor.}
    // The ring's complete new contents; unchanged rows are left alone.
    fun replace(ring: String, rows: List<GeistRingRow>) {
        val a = JSONArray()
        rows.forEach { a.put(JSONObject().put("rowKey", it.rowKey).put("kind", it.kind).put("body", it.body)) }
        call("replace", ring) { put("rows", a) }
    }
    // {.role: actor.}
    fun changePassword(ring: String, password: String) { call("password", ring) { put("password", password) } }
    // {.role: dataWriter.}
    // Writes every unlocked ring that changed, and only those.
    fun save() { call("save", null) }
    // {.role: actor.}
    // Forgets one ring's rows and key; unsaved changes to it are discarded.
    fun lock(ring: String) { call("lock", ring) }
    // {.role: actor.}
    override fun close() {
        if (closed) return
        call("close", null)
        closed = true
    }

    // {.role: helper.}
    private fun call(op: String, ring: String?, extra: JSONObject.() -> Unit = {}): JSONObject {
        check(!closed) { "This vault is closed" }
        val q = JSONObject().put("op", op).put("handle", handle)
        if (ring != null) q.put("ring", ring)
        q.extra()
        return GeistVaultNative.request(q)
    }
}

/** One row of one ring: the app's own id, a grouping, and a body Geist never reads. */
data class GeistRingRow(val rowKey: String, val kind: String, val body: String)

/** A refused vault call. `code` says which kind of refusal it was. */
class GeistVaultException(val code: Int, message: String) : Exception(message) {
    companion object {
        const val BAD_REQUEST = -1
        const val WRONG_PASSWORD = -2
        const val STORAGE = -3
    }
}

/**
 * The two native methods, exported by the Nim bridge itself
 * (src/main/nim/geist_vault_bridge.nim). Requests and answers are UTF-8 JSON
 * bytes; one lock keeps each call paired with its own answer.
 */
internal object GeistVaultNative {
    init {
        System.loadLibrary("geist_vault_nim")
    }
    @JvmStatic private external fun call(request: ByteArray): Int
    @JvmStatic private external fun answer(): ByteArray

    // {.role: orchestrator.}
    @Synchronized
    fun request(q: JSONObject): JSONObject {
        val code = call(q.toString().toByteArray(Charsets.UTF_8))
        val a = JSONObject(String(answer(), Charsets.UTF_8))
        if (code != 0) throw GeistVaultException(code, a.optString("error", "Geist vault call failed"))
        return a
    }
}
