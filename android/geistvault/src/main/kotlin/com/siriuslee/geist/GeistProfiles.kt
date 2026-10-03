package com.siriuslee.geist

import android.content.Context
import android.util.Base64
import org.json.JSONObject
import java.io.File
import java.util.UUID

/**
 * Vault profiles: the list a login screen shows BEFORE anything is
 * unlocked, and the folders the keyrings live in.
 *
 * ```
 *   filesDir/geist-profiles/<namespace>/
 *     <id>/profile.json     public: name, picture, created  (never secret)
 *     <id>/vault/           the keyring set (GeistVault)
 * ```
 *
 * A backup is one JSON text: the profile plus every vault file except
 * rotated copies (`.b1`, `.b2`, ...) and the open-store lock. Every file
 * inside is still sealed, so a backup is as safe as the vault itself.
 *
 * ```
 *   {"format":"geist-profile-1","profile":{...},"files":{"stage1/main.keys.g3":"<base64>", ...}}
 * ```
 */
data class GeistProfile(val id: String, val name: String, val avatarUri: String?, val createdAt: Long)

class GeistProfiles(context: Context, namespace: String) {
    private val root = File(context.filesDir, "geist-profiles/$namespace")

    companion object {
        const val BACKUP_FORMAT = "geist-profile-1"
        // The largest backup accepted; anything bigger is not a vault.
        const val MAX_BACKUP_BYTES = 64 * 1024 * 1024
        private val idPattern = Regex("[A-Za-z0-9-]{8,64}")
        private val skipped = Regex(".*\\.b[0-9]+$|.*\\.geist-lock$")
    }

    // {.role: dataFetcher.}
    fun list(): List<GeistProfile> = (root.listFiles() ?: emptyArray())
        .mapNotNull { dir -> runCatching { read(dir.name) }.getOrNull() }
        .sortedBy { it.createdAt }
    // {.role: parser.}
    fun vaultDir(id: String): File = File(folder(id), "vault")

    // {.role: orchestrator.}
    // Makes the profile and its keyring set; the open vault is handed back.
    fun create(name: String, avatarUri: String?, rings: List<String>, passwords: List<String>): Pair<GeistProfile, GeistVault> {
        val p = GeistProfile(UUID.randomUUID().toString(), name.trim(), avatarUri, System.currentTimeMillis())
        folder(p.id).mkdirs()
        val vault = try { GeistVault.create(vaultDir(p.id), rings, passwords) }
            catch (e: Exception) { folder(p.id).deleteRecursively(); throw e }
        write(p)
        return p to vault
    }
    // {.role: actor.}
    fun rename(id: String, name: String) { write(read(id).copy(name = name.trim())) }
    // {.role: actor.}
    fun setAvatar(id: String, avatarUri: String?) { write(read(id).copy(avatarUri = avatarUri)) }
    // {.role: actor.}
    fun delete(id: String) { folder(id).deleteRecursively() }

    // {.role: dataFetcher.}
    // The whole profile as one sealed text (see the class notes).
    fun export(id: String): String {
        val files = JSONObject()
        val vault = vaultDir(id)
        vault.walkTopDown().filter { it.isFile && !skipped.matches(it.name) }.forEach { f ->
            files.put(f.relativeTo(vault).invariantSeparatorsPath, Base64.encodeToString(f.readBytes(), Base64.NO_WRAP))
        }
        return JSONObject().put("format", BACKUP_FORMAT).put("profile", toJson(read(id))).put("files", files).toString()
    }

    // {.role: sanitizer.}
    // Restores a backup as a NEW profile when its id is already here, so an
    // older backup never overwrites a newer vault.
    fun import(text: String): GeistProfile {
        require(text.length <= MAX_BACKUP_BYTES) { "Backup is too large" }
        val o = JSONObject(text)
        require(o.optString("format") == BACKUP_FORMAT) { "Not a Geist profile backup" }
        var p = fromJson(o.getJSONObject("profile"))
        if (folder(p.id).exists()) p = p.copy(id = UUID.randomUUID().toString(), name = p.name + " (restored)")
        val files = o.getJSONObject("files")
        val vault = vaultDir(p.id)
        try {
            files.keys().forEach { path -> place(vault, path, Base64.decode(files.getString(path), Base64.NO_WRAP)) }
            require(GeistVault.exists(vault)) { "Backup holds no keyring set" }
            write(p)
        } catch (e: Exception) { folder(p.id).deleteRecursively(); throw e }
        return p
    }

    // {.role: dataWriter.}
    // path must stay inside the vault folder: "../" and absolute paths are refused.
    private fun place(vault: File, path: String, bytes: ByteArray) {
        val f = File(vault, path).canonicalFile
        require(f.path.startsWith(vault.canonicalPath + File.separator)) { "Backup path leaves the vault: $path" }
        f.parentFile?.mkdirs()
        f.writeBytes(bytes)
    }
    // {.role: parser.}
    private fun folder(id: String): File {
        require(idPattern.matches(id)) { "Not a profile id: $id" }
        return File(root, id)
    }
    // {.role: dataFetcher.}
    private fun read(id: String): GeistProfile = fromJson(JSONObject(File(folder(id), "profile.json").readText()))
    // {.role: dataWriter.}
    // Written to a side file and renamed, so a crash never leaves half a profile.
    private fun write(p: GeistProfile) {
        val dir = folder(p.id).apply { mkdirs() }
        val tmp = File(dir, "profile.json.tmp")
        tmp.writeText(toJson(p).toString())
        check(tmp.renameTo(File(dir, "profile.json"))) { "Could not save the profile" }
    }
    // {.role: helper.}
    private fun toJson(p: GeistProfile): JSONObject = JSONObject().put("id", p.id).put("name", p.name)
        .put("avatarUri", p.avatarUri ?: JSONObject.NULL).put("createdAt", p.createdAt)
    // {.role: parser.}
    private fun fromJson(o: JSONObject): GeistProfile = GeistProfile(o.getString("id"), o.getString("name"),
        if (o.isNull("avatarUri")) null else o.optString("avatarUri"), o.optLong("createdAt"))
}
