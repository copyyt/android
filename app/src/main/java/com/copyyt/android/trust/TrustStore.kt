package com.copyyt.android.trust

import com.copyyt.android.crypto.CopyytCrypto
import com.copyyt.android.crypto.VerifiedPeer
import com.copyyt.android.net.CopyytJson
import com.copyyt.android.net.DeviceDto
import com.copyyt.android.store.SecureStorage
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer

enum class LocalTrust { ROOT, VERIFIED, UNVERIFIED, REVOKED }

@Serializable
data class LocalDevice(
    val userId: String,
    val deviceId: String,
    val keyVersion: Int,
    val encryptionPublicKey: String,
    val signingPublicKey: String,
    val trust: LocalTrust,
    val name: String? = null,
    val platform: String? = null,
    val capabilities: List<String> = emptyList(),
    /** For a pinned root: the local device it was paired for, and the confirmed fingerprint. */
    val pairedForDeviceId: String? = null,
    val pairingFingerprint: String? = null,
    /** For roots: "initial-tofu" (first device), "recovery", or "pairing" (a pinned remote root). */
    val origin: String? = null,
) {
    val locallyVerified: Boolean get() = trust == LocalTrust.ROOT || trust == LocalTrust.VERIFIED

    /** This device's own root record: it may approve new devices. */
    val approvingRoot: Boolean
        get() = trust == LocalTrust.ROOT && (origin == ORIGIN_FIRST_DEVICE || origin == ORIGIN_RECOVERY)

    companion object {
        const val ORIGIN_FIRST_DEVICE = "initial-tofu"
        const val ORIGIN_RECOVERY = "recovery"
        const val ORIGIN_PAIRING = "pairing"
    }

    fun toPeer() = VerifiedPeer(userId, deviceId, keyVersion, signingPublicKey, encryptionPublicKey)

    fun sameIdentity(other: LocalDevice) =
        deviceId == other.deviceId && keyVersion == other.keyVersion &&
            encryptionPublicKey == other.encryptionPublicKey && signingPublicKey == other.signingPublicKey
}

class TrustException(message: String) : Exception(message)

/**
 * Local trust decisions, ported from the extension's trust store. Server
 * trust labels are never believed: a device becomes trusted only by pairing
 * (the account root, after fingerprint confirmation) or by an approval
 * certificate signed by an already locally verified device. Revocation is
 * sticky and pinned keys can never be replaced.
 */
class TrustStore(private val storage: SecureStorage) {
    private val serializer = ListSerializer(LocalDevice.serializer())
    private val devices: MutableMap<String, LocalDevice> = load()

    private fun load(): MutableMap<String, LocalDevice> =
        storage.read(BLOB)
            ?.let { runCatching { CopyytJson.decodeFromString(serializer, it.toString(Charsets.UTF_8)) }.getOrNull() }
            .orEmpty()
            .associateBy { it.deviceId }
            .toMutableMap()

    private fun persist() = storage.write(
        BLOB,
        CopyytJson.encodeToString(serializer, devices.values.toList()).toByteArray(Charsets.UTF_8),
    )

    @Synchronized
    fun get(deviceId: String): LocalDevice? = devices[deviceId]

    @Synchronized
    fun all(): List<LocalDevice> = devices.values.toList()

    @Synchronized
    fun upsertServerReported(userId: String, device: DeviceDto): LocalDevice {
        val incoming = LocalDevice(
            userId = userId,
            deviceId = device.deviceId,
            keyVersion = device.keyVersion,
            encryptionPublicKey = device.encryptionPublicKey,
            signingPublicKey = device.signingPublicKey,
            trust = if (device.trustState == "revoked") LocalTrust.REVOKED else LocalTrust.UNVERIFIED,
            name = device.name,
            platform = device.platform,
            capabilities = device.capabilities,
        )
        val current = devices[device.deviceId]
        val next = when {
            current?.trust == LocalTrust.REVOKED -> current
            incoming.trust == LocalTrust.REVOKED -> (current ?: incoming).copy(trust = LocalTrust.REVOKED)
            current != null && current.locallyVerified -> {
                if (!current.sameIdentity(incoming) || current.userId != userId) {
                    throw TrustException("A trusted device's keys changed on the server")
                }
                current.copy(
                    name = incoming.name,
                    platform = incoming.platform,
                    capabilities = incoming.capabilities,
                )
            }
            else -> incoming
        }
        devices[device.deviceId] = next
        persist()
        return next
    }

    /** Pins the account root after the user confirmed the pairing fingerprint. */
    @Synchronized
    fun pinPairedRoot(rootDeviceId: String, localDeviceId: String, fingerprint: String): LocalDevice {
        val root = devices[rootDeviceId] ?: throw TrustException("The account root is unknown")
        if (root.trust != LocalTrust.UNVERIFIED) {
            throw TrustException("Only an unverified device can be pinned as the pairing root")
        }
        if (devices.values.any { it.trust == LocalTrust.ROOT }) {
            throw TrustException("A pairing root is already pinned")
        }
        if (rootDeviceId == localDeviceId) throw TrustException("A device cannot pair with itself")
        val pinned = root.copy(
            trust = LocalTrust.ROOT,
            pairedForDeviceId = localDeviceId,
            pairingFingerprint = fingerprint,
            origin = LocalDevice.ORIGIN_PAIRING,
        )
        devices[rootDeviceId] = pinned
        persist()
        return pinned
    }

    /** Promotes a device whose approval certificate verifies against a locally verified approver. */
    @Synchronized
    fun applyApproval(userId: String, device: DeviceDto): Boolean {
        val approverId = device.approvedByDeviceId ?: return false
        val signature = device.approvalSignature ?: return false
        val local = devices[device.deviceId] ?: return false
        if (local.locallyVerified || local.trust == LocalTrust.REVOKED) return false
        val approver = devices[approverId]?.takeIf { it.locallyVerified } ?: return false
        if (local.keyVersion != device.keyVersion ||
            local.encryptionPublicKey != device.encryptionPublicKey ||
            local.signingPublicKey != device.signingPublicKey
        ) {
            throw TrustException("The approved device identity changed on the server")
        }
        val valid = CopyytCrypto.verifyApproval(
            userId, approver.toPeer(), device.deviceId, device.keyVersion,
            device.encryptionPublicKey, device.signingPublicKey, signature,
        )
        if (!valid) return false
        devices[device.deviceId] = local.copy(trust = LocalTrust.VERIFIED)
        persist()
        return true
    }

    /**
     * Makes this device the local trust root, either as the account's first
     * device or after offline recovery. Any previously pinned root is retired.
     */
    @Synchronized
    fun pinSelfAsRoot(self: LocalDevice, origin: String): LocalDevice {
        require(origin == LocalDevice.ORIGIN_FIRST_DEVICE || origin == LocalDevice.ORIGIN_RECOVERY)
        for (device in devices.values.toList()) {
            if (device.trust == LocalTrust.ROOT && device.deviceId != self.deviceId) {
                devices[device.deviceId] = revokedCopy(device)
            }
        }
        val root = self.copy(trust = LocalTrust.ROOT, origin = origin, pairedForDeviceId = null, pairingFingerprint = null)
        devices[self.deviceId] = root
        persist()
        return root
    }

    /** Sticky local revocation: the device never receives keys again. */
    @Synchronized
    fun revoke(deviceId: String) {
        val device = devices[deviceId] ?: return
        devices[deviceId] = revokedCopy(device)
        persist()
    }

    private fun revokedCopy(device: LocalDevice) = device.copy(
        trust = LocalTrust.REVOKED, origin = null, pairedForDeviceId = null, pairingFingerprint = null,
    )

    @Synchronized
    fun clear() {
        devices.clear()
        storage.delete(BLOB)
    }

    private companion object {
        const val BLOB = "trust-devices"
    }
}
