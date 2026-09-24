package com.copyyt.android.store

import com.copyyt.android.crypto.DeviceKeys
import com.copyyt.android.net.CopyytJson
import com.copyyt.android.protocol.B64
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.serializer
import java.util.UUID

/**
 * Durable, integrity-protected storage for small state blobs. The Android
 * implementation encrypts each blob with a non-exportable Keystore key.
 */
interface SecureStorage {
    fun read(name: String): ByteArray?
    fun write(name: String, bytes: ByteArray)
    fun delete(name: String)
}

class InMemoryStorage : SecureStorage {
    private val blobs = mutableMapOf<String, ByteArray>()
    override fun read(name: String) = blobs[name]?.copyOf()
    override fun write(name: String, bytes: ByteArray) { blobs[name] = bytes.copyOf() }
    override fun delete(name: String) { blobs.remove(name) }
}

private class JsonBlob<T>(
    private val storage: SecureStorage,
    private val name: String,
    private val serializer: KSerializer<T>,
) {
    fun load(): T? = storage.read(name)?.let {
        runCatching { CopyytJson.decodeFromString(serializer, it.toString(Charsets.UTF_8)) }.getOrNull()
    }

    fun save(value: T) =
        storage.write(name, CopyytJson.encodeToString(serializer, value).toByteArray(Charsets.UTF_8))

    fun clear() = storage.delete(name)
}

@Serializable
data class Session(
    val accessToken: String,
    val refreshToken: String,
    val userId: String,
    val email: String,
    val name: String? = null,
)

/** This phone's own settings; they don't follow the account to other devices. */
@Serializable
data class DevicePreferences(val receiveEnabled: Boolean = true)

class PreferencesStore(storage: SecureStorage) {
    private val blob = JsonBlob(storage, "device-preferences", DevicePreferences.serializer())
    fun get(): DevicePreferences = blob.load() ?: DevicePreferences()
    fun set(preferences: DevicePreferences) = blob.save(preferences)
}

class SessionStore(storage: SecureStorage) {
    private val blob = JsonBlob(storage, "session", Session.serializer())
    fun get(): Session? = blob.load()
    fun set(session: Session) = blob.save(session)
    fun clear() = blob.clear()
}

@Serializable
private data class StoredIdentity(
    val userId: String,
    val deviceId: String,
    val signingSeed: String,
    val encryptionPrivateKey: String,
    val keyVersion: Int? = null,
    /** Root only: public half of the offline recovery credential. */
    val recoveryPublicKey: String? = null,
    /** Root only, until the user confirms they saved it offline. */
    val recoverySeed: String? = null,
    val recoveryExportedAt: String? = null,
)

class DeviceIdentity(
    val userId: String,
    val deviceId: String,
    val keys: DeviceKeys,
    /** Server key version once registered; null before the first registration. */
    val keyVersion: Int?,
    val recoveryPublicKey: String? = null,
    val recoverySeed: ByteArray? = null,
    val recoveryExportedAt: String? = null,
)

/**
 * One device identity per account, like the extension's per-user key store.
 * Each account has its own blob, so signing in to another account never
 * replaces this one's keys.
 */
class IdentityStore(private val storage: SecureStorage) {
    private fun blob(userId: String) = JsonBlob(storage, "identity-$userId", StoredIdentity.serializer())

    /** Moves an identity saved by versions that kept a single account. */
    private fun migrateLegacy(userId: String) {
        val legacy = JsonBlob(storage, LEGACY_BLOB, StoredIdentity.serializer())
        val stored = legacy.load() ?: return
        val target = blob(stored.userId)
        if (target.load() == null) target.save(stored)
        legacy.clear()
    }

    private fun load(userId: String): StoredIdentity? {
        migrateLegacy(userId)
        return blob(userId).load()?.takeIf { it.userId == userId }
    }

    fun get(userId: String): DeviceIdentity? = load(userId)?.let {
        DeviceIdentity(
            it.userId, it.deviceId,
            DeviceKeys(B64.decode(it.signingSeed), B64.decode(it.encryptionPrivateKey)),
            it.keyVersion,
            it.recoveryPublicKey,
            it.recoverySeed?.let(B64::decode),
            it.recoveryExportedAt,
        )
    }

    fun getOrCreate(userId: String): DeviceIdentity = get(userId) ?: run {
        val keys = DeviceKeys.generate()
        val created = StoredIdentity(
            userId = userId,
            deviceId = UUID.randomUUID().toString(),
            signingSeed = B64.encode(keys.signingSeed),
            encryptionPrivateKey = B64.encode(keys.encryptionPrivateKey),
        )
        blob(userId).save(created)
        get(userId)!!
    }

    private fun update(identity: DeviceIdentity, change: (StoredIdentity) -> StoredIdentity): DeviceIdentity {
        val current = load(identity.userId) ?: error("No device identity")
        require(current.deviceId == identity.deviceId) { "Device identity changed" }
        blob(identity.userId).save(change(current))
        return get(identity.userId)!!
    }

    fun setKeyVersion(identity: DeviceIdentity, keyVersion: Int): DeviceIdentity =
        update(identity) { it.copy(keyVersion = keyVersion) }

    /** Creates the offline recovery key pair if this identity has none yet. */
    fun ensureRecoveryKey(identity: DeviceIdentity): DeviceIdentity =
        if (identity.recoveryPublicKey != null) identity
        else setRecoveryKey(identity, com.google.crypto.tink.subtle.Ed25519Sign.KeyPair.newKeyPair().privateKey)

    /** Installs a (new or rotated) recovery key; it is exportable again. */
    fun setRecoveryKey(identity: DeviceIdentity, seed: ByteArray): DeviceIdentity {
        val publicKey = com.google.crypto.tink.subtle.Ed25519Sign.KeyPair.newKeyPairFromSeed(seed).publicKey
        return update(identity) {
            it.copy(
                recoveryPublicKey = B64.encode(publicKey),
                recoverySeed = B64.encode(seed),
                recoveryExportedAt = null,
            )
        }
    }

    /** Deletes the recovery private key once the user saved it offline. */
    fun sealRecovery(identity: DeviceIdentity, exportedAt: String): DeviceIdentity =
        update(identity) { it.copy(recoverySeed = null, recoveryExportedAt = exportedAt) }

    /** Forgets this account's identity only; other accounts keep theirs. */
    fun clear(userId: String) {
        migrateLegacy(userId)
        blob(userId).clear()
    }

    private companion object {
        const val LEGACY_BLOB = "identity"
    }
}

/** Bounded record of handled item IDs so replays are never re-applied. */
class ProcessedItems(storage: SecureStorage, private val capacity: Int = 500) {
    private val blob = JsonBlob(storage, "processed-items", ListSerializer(String.serializer()))

    @Synchronized
    fun contains(itemId: String): Boolean = blob.load().orEmpty().contains(itemId)

    @Synchronized
    fun mark(itemId: String) {
        val ids = blob.load().orEmpty().filter { it != itemId } + itemId
        blob.save(ids.takeLast(capacity))
    }

    fun clear() = blob.clear()
}
