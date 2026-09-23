package com.psami.copyyt.android

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.psami.copyyt.store.SecureStorage
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Encrypts every state blob (device private keys, session tokens, trust
 * decisions) with a non-exportable AES-256-GCM key held by Android Keystore.
 * The blob name is bound as associated data so blobs cannot be swapped.
 */
class KeystoreStorage(context: Context) : SecureStorage {
    private val dir = File(context.noBackupFilesDir, "copyyt-state").apply { mkdirs() }

    private fun key(): SecretKey {
        val keyStore = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        (keyStore.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build(),
        )
        return generator.generateKey()
    }

    private fun file(name: String) = File(dir, "$name.bin")

    @Synchronized
    override fun read(name: String): ByteArray? {
        val file = file(name)
        if (!file.exists()) return null
        return runCatching {
            val bytes = file.readBytes()
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, bytes, 0, IV_BYTES))
            cipher.updateAAD(name.toByteArray(Charsets.UTF_8))
            cipher.doFinal(bytes, IV_BYTES, bytes.size - IV_BYTES)
        }.getOrNull()
    }

    @Synchronized
    override fun write(name: String, bytes: ByteArray) {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key())
        cipher.updateAAD(name.toByteArray(Charsets.UTF_8))
        val sealed = cipher.iv + cipher.doFinal(bytes)
        val tmp = File(dir, "$name.tmp")
        tmp.writeBytes(sealed)
        if (!tmp.renameTo(file(name))) {
            file(name).writeBytes(sealed)
            tmp.delete()
        }
    }

    @Synchronized
    override fun delete(name: String) {
        file(name).delete()
    }

    private companion object {
        const val KEYSTORE = "AndroidKeyStore"
        const val ALIAS = "copyyt-state-v1"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val IV_BYTES = 12
    }
}
