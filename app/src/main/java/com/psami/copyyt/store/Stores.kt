package com.psami.copyyt.store

import com.psami.copyyt.crypto.DeviceKeys
import com.psami.copyyt.net.CopyytJson
import com.psami.copyyt.protocol.B64
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

/** One device identity per account, like the extension's per-user key store. */
class IdentityStore(storage: SecureStorage) {
    private val blob = JsonBlob(storage, "identity", StoredIdentity.serializer())

    fun get(userId: String): DeviceIdentity? = blob.load()
        ?.takeIf { it.userId == userId }
        ?.let {
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
        blob.save(created)
        get(userId)!!
    }

    fun setKeyVersion(identity: DeviceIdentity, keyVersion: Int): DeviceIdentity {
        val current = blob.load() ?: error("No device identity")
        require(current.deviceId == identity.deviceId) { "Device identity changed" }
        blob.save(current.copy(keyVersion = keyVersion))
        return get(identity.userId)!!
    }

    /** Creates the offline recovery key pair if this identity has none yet. */
    fun ensureRecoveryKey(identity: DeviceIdentity): DeviceIdentity =
        if (identity.recoveryPublicKey != null) identity
        else setRecoveryKey(identity, com.google.crypto.tink.subtle.Ed25519Sign.KeyPair.newKeyPair().privateKey)

    /** Installs a (new or rotated) recovery key; it is exportable again. */
    fun setRecoveryKey(identity: DeviceIdentity, seed: ByteArray): DeviceIdentity {
        val current = blob.load() ?: error("No device identity")
        require(current.deviceId == identity.deviceId) { "Device identity changed" }
        val publicKey = com.google.crypto.tink.subtle.Ed25519Sign.KeyPair.newKeyPairFromSeed(seed).publicKey
        blob.save(
            current.copy(
                recoveryPublicKey = B64.encode(publicKey),
                recoverySeed = B64.encode(seed),
                recoveryExportedAt = null,
            ),
        )
        return get(identity.userId)!!
    }

    /** Deletes the recovery private key once the user saved it offline. */
    fun sealRecovery(identity: DeviceIdentity, exportedAt: String): DeviceIdentity {
        val current = blob.load() ?: error("No device identity")
        require(current.deviceId == identity.deviceId) { "Device identity changed" }
        blob.save(current.copy(recoverySeed = null, recoveryExportedAt = exportedAt))
        return get(identity.userId)!!
    }

    fun clear() = blob.clear()
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
