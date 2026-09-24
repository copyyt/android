package com.copyyt.android

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.copyyt.android.app.KeystoreStorage
import com.copyyt.android.store.IdentityStore
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

@RunWith(AndroidJUnit4::class)
class KeystoreStorageTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    @Test
    fun roundTripsEncryptedBlobsAndNeverStoresPlaintext() {
        val storage = KeystoreStorage(context)
        val secret = "private-seed-material".toByteArray()
        storage.write("test-blob", secret)
        assertArrayEquals(secret, KeystoreStorage(context).read("test-blob"))
        val onDisk = File(context.noBackupFilesDir, "copyyt-state/test-blob.bin").readBytes()
        assertFalse(String(onDisk, Charsets.ISO_8859_1).contains("private-seed-material"))
        storage.delete("test-blob")
        assertNull(storage.read("test-blob"))
    }

    @Test
    fun aBlobCannotBeReadUnderAnotherName() {
        val storage = KeystoreStorage(context)
        storage.write("blob-a", "a".toByteArray())
        val dir = File(context.noBackupFilesDir, "copyyt-state")
        File(dir, "blob-a.bin").copyTo(File(dir, "blob-b.bin"), overwrite = true)
        assertNull("associated data binds each blob to its name", storage.read("blob-b"))
        storage.delete("blob-a")
        storage.delete("blob-b")
    }

    @Test
    fun deviceIdentitySurvivesAReload() {
        val first = IdentityStore(KeystoreStorage(context)).getOrCreate("user-1")
        val reloaded = IdentityStore(KeystoreStorage(context)).get("user-1")!!
        assertEquals(first.deviceId, reloaded.deviceId)
        assertEquals(first.keys.signingPublicKeyBase64, reloaded.keys.signingPublicKeyBase64)
        IdentityStore(KeystoreStorage(context)).clear("user-1")
    }
}
