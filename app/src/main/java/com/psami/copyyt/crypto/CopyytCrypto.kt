package com.psami.copyyt.crypto

import com.google.crypto.tink.subtle.Ed25519Sign
import com.google.crypto.tink.subtle.Ed25519Verify
import com.google.crypto.tink.subtle.Hkdf
import com.google.crypto.tink.subtle.X25519
import com.psami.copyyt.protocol.B64
import com.psami.copyyt.protocol.Protocol
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class CryptoProtocolException(message: String) : Exception(message)

/** Raw key material for this device. Private halves never leave the process unwrapped. */
class DeviceKeys(
    val signingSeed: ByteArray,
    val encryptionPrivateKey: ByteArray,
) {
    val signingPublicKey: ByteArray =
        Ed25519Sign.KeyPair.newKeyPairFromSeed(signingSeed).publicKey
    val encryptionPublicKey: ByteArray = X25519.publicFromPrivate(encryptionPrivateKey)
    val signingPublicKeyBase64: String get() = B64.encode(signingPublicKey)
    val encryptionPublicKeyBase64: String get() = B64.encode(encryptionPublicKey)

    fun sign(message: ByteArray): ByteArray = Ed25519Sign(signingSeed).sign(message)

    companion object {
        fun generate(): DeviceKeys = DeviceKeys(
            signingSeed = Ed25519Sign.KeyPair.newKeyPair().privateKey,
            encryptionPrivateKey = X25519.generatePrivateKey(),
        )
    }
}

/** A peer the local trust store has verified (root or verified), never a server label. */
data class VerifiedPeer(
    val userId: String,
    val deviceId: String,
    val keyVersion: Int,
    val signingPublicKey: String,
    val encryptionPublicKey: String,
)

data class EnvelopeRecipient(
    val deviceId: String,
    val deviceKeyVersion: Int,
    val wrapNonce: String,
    val wrappedContentKey: String,
)

data class Envelope(
    val itemId: String,
    val sourceDeviceId: String,
    val sourceKeyVersion: Int,
    val sourceSignature: String,
    val protocolVersion: Int,
    val contentType: String,
    val ciphertext: String,
    val nonce: String,
    val recipients: List<EnvelopeRecipient>,
    val expiresAt: String,
)

/** Port of the extension's crypto-core: Ed25519, X25519 + HKDF-SHA256, AES-256-GCM. */
object CopyytCrypto {
    private const val KEY_BYTES = 32
    private const val NONCE_BYTES = 12
    private const val TAG_BITS = 128
    const val WRAPPED_KEY_BYTES = 48
    const val MAX_PLAINTEXT_BYTES = 1024 * 1024 - 16

    private val random = SecureRandom()
    private val hkdfSalt: ByteArray =
        Protocol.sha256(Protocol.KEY_WRAP_HKDF_SALT.toByteArray(Charsets.UTF_8))

    fun randomBytes(length: Int): ByteArray = ByteArray(length).also { random.nextBytes(it) }

    fun verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
        if (publicKey.size != 32 || signature.size != 64) return false
        return try {
            Ed25519Verify(publicKey).verify(signature, message)
            true
        } catch (_: Exception) {
            false
        }
    }

    private fun wrappingKey(
        privateKey: ByteArray,
        peerPublicKey: ByteArray,
        context: ByteArray,
    ): ByteArray {
        if (peerPublicKey.size != 32) throw CryptoProtocolException("Public key must be 32 bytes")
        val shared = X25519.computeSharedSecret(privateKey, peerPublicKey)
        return Hkdf.computeHkdf("HMACSHA256", shared, hkdfSalt, context, KEY_BYTES)
    }

    private fun aesGcm(
        mode: Int,
        key: ByteArray,
        nonce: ByteArray,
        aad: ByteArray,
        input: ByteArray,
    ): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(mode, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, nonce))
        cipher.updateAAD(aad)
        return cipher.doFinal(input)
    }

    fun encryptText(
        userId: String,
        localDeviceId: String,
        localKeyVersion: Int,
        keys: DeviceKeys,
        plaintext: ByteArray,
        contentType: String,
        expiresAt: String,
        recipients: List<VerifiedPeer>,
        itemId: String = java.util.UUID.randomUUID().toString(),
        random: (Int) -> ByteArray = ::randomBytes,
    ): Envelope {
        if (recipients.isEmpty()) {
            throw CryptoProtocolException("At least one locally verified recipient is required")
        }
        if (recipients.any { it.userId != userId }) {
            throw CryptoProtocolException("An encryption recipient belongs to another account")
        }
        if (recipients.map { it.deviceId }.toSet().size != recipients.size) {
            throw CryptoProtocolException("Each encryption recipient may appear only once")
        }
        if (plaintext.size > MAX_PLAINTEXT_BYTES) {
            throw CryptoProtocolException("Clipboard plaintext exceeds the encrypted payload size limit")
        }
        val canonicalExpiry = Protocol.canonicalExpiry(expiresAt)
        val aad = Protocol.payloadAad(
            userId, Protocol.CRYPTO_PROTOCOL_VERSION, itemId, localDeviceId,
            localKeyVersion, contentType, canonicalExpiry,
        )
        val contentKey = random(KEY_BYTES)
        val payloadNonce = random(NONCE_BYTES)
        val ciphertext = aesGcm(Cipher.ENCRYPT_MODE, contentKey, payloadNonce, aad, plaintext)
        val wrapped = recipients.map { recipient ->
            val wrapNonce = random(NONCE_BYTES)
            val context = Protocol.keyWrapContext(
                userId, Protocol.CRYPTO_PROTOCOL_VERSION, itemId, localDeviceId,
                localKeyVersion, recipient.deviceId, recipient.keyVersion,
            )
            val key = wrappingKey(
                keys.encryptionPrivateKey,
                B64.decodeExact(recipient.encryptionPublicKey, 32),
                context,
            )
            EnvelopeRecipient(
                deviceId = recipient.deviceId,
                deviceKeyVersion = recipient.keyVersion,
                wrapNonce = B64.encode(wrapNonce),
                wrappedContentKey = B64.encode(
                    aesGcm(Cipher.ENCRYPT_MODE, key, wrapNonce, context, contentKey),
                ),
            )
        }
        val signature = keys.sign(
            Protocol.clipboardEnvelopeSignatureMessage(
                userId, Protocol.CRYPTO_PROTOCOL_VERSION, itemId, localDeviceId,
                localKeyVersion, contentType, payloadNonce, ciphertext, canonicalExpiry,
            ),
        )
        return Envelope(
            itemId = itemId,
            sourceDeviceId = localDeviceId,
            sourceKeyVersion = localKeyVersion,
            sourceSignature = B64.encode(signature),
            protocolVersion = Protocol.CRYPTO_PROTOCOL_VERSION,
            contentType = contentType,
            ciphertext = B64.encode(ciphertext),
            nonce = B64.encode(payloadNonce),
            recipients = wrapped,
            expiresAt = canonicalExpiry,
        )
    }

    /**
     * Authenticates and decrypts an incoming single-recipient envelope. The
     * source must be a peer the local trust store verified, at the exact key
     * version the envelope claims.
     */
    fun decrypt(
        userId: String,
        localDeviceId: String,
        localKeyVersion: Int,
        keys: DeviceKeys,
        source: VerifiedPeer,
        envelope: Envelope,
    ): ByteArray {
        if (envelope.protocolVersion != Protocol.CRYPTO_PROTOCOL_VERSION) {
            throw CryptoProtocolException("Unsupported clipboard protocol version")
        }
        if (source.userId != userId) {
            throw CryptoProtocolException("The source device belongs to another account")
        }
        if (source.deviceId != envelope.sourceDeviceId ||
            source.keyVersion != envelope.sourceKeyVersion
        ) {
            throw CryptoProtocolException("The source device key version is not verified")
        }
        val nonce = decodeOrFail(envelope.nonce, NONCE_BYTES, "Payload nonce")
        val ciphertext = runCatching { B64.decode(envelope.ciphertext) }
            .getOrElse { throw CryptoProtocolException("Invalid ciphertext encoding") }
        val signature = decodeOrFail(envelope.sourceSignature, 64, "Source signature")
        val signed = Protocol.clipboardEnvelopeSignatureMessage(
            userId, envelope.protocolVersion, envelope.itemId, envelope.sourceDeviceId,
            envelope.sourceKeyVersion, envelope.contentType, nonce, ciphertext, envelope.expiresAt,
        )
        if (!verify(B64.decode(source.signingPublicKey), signed, signature)) {
            throw CryptoProtocolException("The source envelope signature is invalid")
        }
        val recipient = envelope.recipients.singleOrNull()
            ?: throw CryptoProtocolException("An incoming device envelope must contain exactly one recipient")
        if (recipient.deviceId != localDeviceId) {
            throw CryptoProtocolException("The clipboard item is addressed to another device")
        }
        if (recipient.deviceKeyVersion != localKeyVersion) {
            throw CryptoProtocolException("The recipient key version is not current")
        }
        val context = Protocol.keyWrapContext(
            userId, Protocol.CRYPTO_PROTOCOL_VERSION, envelope.itemId, envelope.sourceDeviceId,
            envelope.sourceKeyVersion, recipient.deviceId, recipient.deviceKeyVersion,
        )
        val wrapKey = wrappingKey(
            keys.encryptionPrivateKey,
            B64.decodeExact(source.encryptionPublicKey, 32),
            context,
        )
        val contentKey = try {
            aesGcm(
                Cipher.DECRYPT_MODE, wrapKey,
                decodeOrFail(recipient.wrapNonce, NONCE_BYTES, "Key-wrap nonce"),
                context,
                decodeOrFail(recipient.wrappedContentKey, WRAPPED_KEY_BYTES, "Wrapped content key"),
            )
        } catch (_: CryptoProtocolException) {
            throw CryptoProtocolException("Content-key unwrap failed")
        } catch (_: Exception) {
            throw CryptoProtocolException("Content-key unwrap failed")
        }
        if (contentKey.size != KEY_BYTES) throw CryptoProtocolException("Unwrapped content key")
        val aad = Protocol.payloadAad(
            userId, envelope.protocolVersion, envelope.itemId, envelope.sourceDeviceId,
            envelope.sourceKeyVersion, envelope.contentType, envelope.expiresAt,
        )
        return try {
            aesGcm(Cipher.DECRYPT_MODE, contentKey, nonce, aad, ciphertext)
        } catch (_: Exception) {
            throw CryptoProtocolException("Clipboard payload authentication failed")
        }
    }

    fun verifyApproval(
        userId: String,
        approver: VerifiedPeer,
        pendingDeviceId: String,
        pendingKeyVersion: Int,
        pendingEncryptionPublicKey: String,
        pendingSigningPublicKey: String,
        approvalSignature: String,
    ): Boolean {
        if (approver.userId != userId ||
            !B64.isExact(approvalSignature, 64) ||
            !B64.isExact(pendingEncryptionPublicKey, 32) ||
            !B64.isExact(pendingSigningPublicKey, 32) ||
            !B64.isExact(approver.signingPublicKey, 32)
        ) {
            return false
        }
        return verify(
            B64.decode(approver.signingPublicKey),
            Protocol.deviceApprovalMessage(
                userId, approver.deviceId, approver.keyVersion, pendingDeviceId,
                pendingKeyVersion, pendingEncryptionPublicKey, pendingSigningPublicKey,
            ),
            B64.decode(approvalSignature),
        )
    }

    private fun decodeOrFail(value: String, length: Int, label: String): ByteArray =
        runCatching { B64.decodeExact(value, length) }
            .getOrElse { throw CryptoProtocolException("$label must be exactly $length bytes") }
}
