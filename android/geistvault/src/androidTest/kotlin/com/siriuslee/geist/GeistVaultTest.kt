package com.siriuslee.geist

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/**
 * Runs the real Nim library on the device: sealing, Argon2id and the JNI
 * byte copies are exactly what an app gets.
 */
@RunWith(AndroidJUnit4::class)
class GeistVaultTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    // {.role: helper.}
    private fun fresh(name: String): File = File(context.cacheDir, name).apply { deleteRecursively() }

    // {.testKind: tkIntegration, covers: "GeistVault.create|GeistVault.open|GeistVault.unlock|GeistVault.rows".}
    @Test fun ringsOpenOnlyWithTheirOwnPassword() {
        val dir = fresh("vault-open")
        GeistVault.create(dir, listOf("stage1", "stage2"), listOf("p1", "p1|p2")).use { v ->
            v.replace("stage1", listOf(GeistRingRow("card-1", "accounts", "{\"title\":\"ᚠ Mail ✓ 🗝\"}")))
            v.replace("stage2", listOf(GeistRingRow("card-1", "accounts", "{\"secret\":\"x\"}")))
            v.save()
        }
        GeistVault.open(dir).use { v ->
            assertEquals(listOf("stage1", "stage2"), v.rings)
            assertFalse(v.unlock("stage2", "p1"))
            assertTrue(v.unlock("stage1", "p1"))
            // Runes and emoji survive the byte-level JNI copy.
            assertEquals("{\"title\":\"ᚠ Mail ✓ 🗝\"}", v.rows("stage1").single().body)
            assertThrows(GeistVaultException::class.java) { v.rows("stage2") }
        }
    }

    // {.testKind: tkRegression, covers: "GeistVault.save", pins: "a save with only stage 1 open must not touch stage 2".}
    @Test fun savingOneRingLeavesTheOtherUntouched() {
        val dir = fresh("vault-partial")
        GeistVault.create(dir, listOf("stage1", "stage2"), listOf("a", "b")).use { v ->
            v.replace("stage2", listOf(GeistRingRow("k", "c", "secret-sentinel"))); v.save()
        }
        val before = File(dir, "stage2").walkTopDown().filter { it.isFile }.associate { it.name to it.readBytes().toList() }
        GeistVault.open(dir).use { v ->
            assertTrue(v.unlock("stage1", "a"))
            v.replace("stage1", listOf(GeistRingRow("p", "patterns", "new"))); v.save()
        }
        val after = File(dir, "stage2").walkTopDown().filter { it.isFile }.associate { it.name to it.readBytes().toList() }
        assertEquals(before, after)
        dir.walkTopDown().filter { it.isFile }.forEach { assertFalse(String(it.readBytes(), Charsets.ISO_8859_1).contains("secret-sentinel")) }
    }

    // {.testKind: tkIntegration, covers: "GeistProfiles.create|GeistProfiles.export|GeistProfiles.import|GeistVault.changePassword".}
    @Test fun profilesExportImportAndChangePasswords() {
        val profiles = GeistProfiles(context, "geistVaultTest")
        profiles.list().forEach { profiles.delete(it.id) }
        val (p, v) = profiles.create("Alex", null, listOf("stage1"), listOf("old"))
        v.replace("stage1", listOf(GeistRingRow("r", "k", "kept"))); v.changePassword("stage1", "new"); v.save(); v.close()
        assertEquals(listOf("Alex"), profiles.list().map { it.name })
        val backup = profiles.export(p.id)
        assertFalse(backup.contains("kept"))
        val copy = profiles.import(backup)
        assertNotEquals(p.id, copy.id)
        GeistVault.open(profiles.vaultDir(copy.id)).use { w ->
            assertFalse(w.unlock("stage1", "old"))
            assertTrue(w.unlock("stage1", "new"))
            assertEquals("kept", w.rows("stage1").single().body)
        }
        assertThrows(IllegalArgumentException::class.java) {
            // org.json writes "/" as "\\/"; both spellings are swapped for a path that climbs out.
            profiles.import(backup.replace("stage1\\/", "..\\/..\\/").replace("stage1/", "../../"))
        }
        profiles.list().forEach { profiles.delete(it.id) }
    }
}
