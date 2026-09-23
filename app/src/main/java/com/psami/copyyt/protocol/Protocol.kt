package com.psami.copyyt.protocol

import java.security.MessageDigest
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.Base64

/**
 * Canonical Copyyt v1 protocol messages. Every builder must produce exactly
 * the bytes of the extension's `crypto/protocol.ts` and the backend; the
 * cross-platform fixture test (ProtocolFixtureTest) pins this.
 */
object Protocol {
    const val CRYPTO_PROTOCOL_VERSION = 1
    const val DEVICE_APPROVAL_MESSAGE_VERSION = "copyyt-device-approval-v1"
    const val DEVICE_MANAGEMENT_MESSAGE_VERSION = "copyyt-device-management-v1"
    const val DEVICE_RECOVERY_MESSAGE_VERSION = "copyyt-device-recovery-v1"
    const val CLIPBOARD_ENVELOPE_SIGNATURE_MESSAGE_VERSION = "copyyt-clipboard-envelope-v1"
    const val SOCKET_AUTH_MESSAGE_VERSION = "copyyt-socket-auth-v1"
    const val KEY_WRAP_CONTEXT_VERSION = "copyyt-key-wrap-v1"
    const val KEY_WRAP_HKDF_SALT = "copyyt-key-wrap-hkdf-salt-v1"
    const val PAYLOAD_AAD_VERSION = "copyyt-payload-v1"
    const val PAIRING_FINGERPRINT_CONTEXT_VERSION = "copyyt-pairing-fingerprint-v1"

    private val isoMillis: DateTimeFormatter =
        DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").withZone(ZoneOffset.UTC)

    /** JavaScript `Date.prototype.toISOString()`: always millisecond precision, UTC. */
    fun canonicalExpiry(value: Instant): String = isoMillis.format(value)

    fun canonicalExpiry(value: String): String = canonicalExpiry(parseIso(value))

    fun parseIso(value: String): Instant = Instant.parse(value)

    private fun canonicalLines(lines: List<String>): ByteArray =
        (lines.joinToString("\n") + "\n").toByteArray(Charsets.UTF_8)

    private fun lengthPrefixed(version: String, fields: List<Pair<String, Any>>): ByteArray {
        val parts = listOf(version) + fields.map { (key, value) -> "$key=$value" }
        return parts.joinToString("") { part ->
            "${part.toByteArray(Charsets.UTF_8).size}:$part"
        }.toByteArray(Charsets.UTF_8)
    }

    fun deviceApprovalMessage(
        userId: String,
        approvingDeviceId: String,
        approvingKeyVersion: Int,
        pendingDeviceId: String,
        pendingKeyVersion: Int,
        pendingEncryptionPublicKey: String,
        pendingSigningPublicKey: String,
    ): ByteArray = canonicalLines(
        listOf(
            DEVICE_APPROVAL_MESSAGE_VERSION,
            "userId=$userId",
            "approvingDeviceId=$approvingDeviceId",
            "approvingKeyVersion=$approvingKeyVersion",
            "pendingDeviceId=$pendingDeviceId",
            "pendingKeyVersion=$pendingKeyVersion",
            "pendingEncryptionPublicKey=$pendingEncryptionPublicKey",
            "pendingSigningPublicKey=$pendingSigningPublicKey",
        ),
    )

    /** Mirrors the extension's JSON.stringify(string[]) for capability lists. */
    fun jsonStringArray(values: List<String>): String =
        values.joinToString(",", "[", "]") { jsonString(it) }

    private fun jsonString(value: String): String {
        val out = StringBuilder("\"")
        for (ch in value) {
            when {
                ch == '"' -> out.append("\\\"")
                ch == '\\' -> out.append("\\\\")
                ch == '\n' -> out.append("\\n")
                ch == '\r' -> out.append("\\r")
                ch == '\t' -> out.append("\\t")
                ch == '\b' -> out.append("\\b")
                ch == '\u000C' -> out.append("\\f")
                ch < ' ' -> out.append(String.format("\\u%04x", ch.code))
                else -> out.append(ch)
            }
        }
        return out.append('"').toString()
    }

    fun deviceManagementMessage(
        action: String,
        userId: String,
        requestingDeviceId: String,
        requestingKeyVersion: Int,
        targetDeviceId: String,
        targetKeyVersion: Int,
        timestamp: Long,
        nonce: String,
        name: String?,
        platform: String?,
        capabilities: List<String>?,
        appVersion: String?,
        recoveryPublicKey: String?,
    ): ByteArray = lengthPrefixed(
        DEVICE_MANAGEMENT_MESSAGE_VERSION,
        listOf(
            "action" to action,
            "userId" to userId,
            "requestingDeviceId" to requestingDeviceId,
            "requestingKeyVersion" to requestingKeyVersion,
            "targetDeviceId" to targetDeviceId,
            "targetKeyVersion" to targetKeyVersion,
            "timestamp" to timestamp,
            "nonce" to nonce,
            "name" to (name ?: ""),
            "platform" to (platform ?: ""),
            "capabilities" to jsonStringArray(capabilities ?: emptyList()),
            "appVersion" to (appVersion ?: ""),
            "recoveryPublicKey" to (recoveryPublicKey ?: ""),
        ),
    )

    fun deviceRecoveryMessage(
        userId: String,
        rootDeviceId: String,
        deviceId: String,
        name: String,
        platform: String,
        encryptionPublicKey: String,
        signingPublicKey: String,
        capabilities: List<String>,
        appVersion: String?,
        timestamp: Long,
        nonce: String,
        newRecoveryPublicKey: String,
    ): ByteArray = lengthPrefixed(
        DEVICE_RECOVERY_MESSAGE_VERSION,
        listOf(
            "userId" to userId,
            "rootDeviceId" to rootDeviceId,
            "deviceId" to deviceId,
            "name" to name,
            "platform" to platform,
            "encryptionPublicKey" to encryptionPublicKey,
            "signingPublicKey" to signingPublicKey,
            "capabilities" to jsonStringArray(capabilities),
            "appVersion" to (appVersion ?: ""),
            "timestamp" to timestamp,
            "nonce" to nonce,
            "newRecoveryPublicKey" to newRecoveryPublicKey,
        ),
    )

    fun socketAuthMessage(
        userId: String,
        deviceId: String,
        keyVersion: Int,
        socketId: String,
        challenge: String,
    ): ByteArray = canonicalLines(
        listOf(
            SOCKET_AUTH_MESSAGE_VERSION,
            "userId=$userId",
            "deviceId=$deviceId",
            "keyVersion=$keyVersion",
            "socketId=$socketId",
            "challenge=$challenge",
        ),
    )

    fun clipboardEnvelopeSignatureMessage(
        userId: String,
        protocolVersion: Int,
        itemId: String,
        sourceDeviceId: String,
        sourceKeyVersion: Int,
        contentType: String,
        nonce: ByteArray,
        ciphertext: ByteArray,
        expiresAt: String,
    ): ByteArray = canonicalLines(
        listOf(
            CLIPBOARD_ENVELOPE_SIGNATURE_MESSAGE_VERSION,
            "userId=$userId",
            "protocolVersion=$protocolVersion",
            "itemId=$itemId",
            "sourceDeviceId=$sourceDeviceId",
            "sourceKeyVersion=$sourceKeyVersion",
            "contentType=$contentType",
            "nonce=${B64.encode(nonce)}",
            "ciphertextSha256=${B64.encode(sha256(ciphertext))}",
            "expiresAt=${canonicalExpiry(expiresAt)}",
        ),
    )

    fun keyWrapContext(
        userId: String,
        protocolVersion: Int,
        itemId: String,
        sourceDeviceId: String,
        sourceKeyVersion: Int,
        recipientDeviceId: String,
        recipientKeyVersion: Int,
    ): ByteArray = canonicalLines(
        listOf(
            KEY_WRAP_CONTEXT_VERSION,
            "userId=$userId",
            "protocolVersion=$protocolVersion",
            "itemId=$itemId",
            "sourceDeviceId=$sourceDeviceId",
            "sourceKeyVersion=$sourceKeyVersion",
            "recipientDeviceId=$recipientDeviceId",
            "recipientKeyVersion=$recipientKeyVersion",
        ),
    )

    fun payloadAad(
        userId: String,
        protocolVersion: Int,
        itemId: String,
        sourceDeviceId: String,
        sourceKeyVersion: Int,
        contentType: String,
        expiresAt: String,
    ): ByteArray = canonicalLines(
        listOf(
            PAYLOAD_AAD_VERSION,
            "userId=$userId",
            "protocolVersion=$protocolVersion",
            "itemId=$itemId",
            "sourceDeviceId=$sourceDeviceId",
            "sourceKeyVersion=$sourceKeyVersion",
            "contentType=$contentType",
            "expiresAt=${canonicalExpiry(expiresAt)}",
        ),
    )

    fun pairingFingerprintContext(
        userId: String,
        approvingDeviceId: String,
        approvingKeyVersion: Int,
        approvingSigningPublicKey: String,
        approvingEncryptionPublicKey: String,
        pendingDeviceId: String,
        pendingKeyVersion: Int,
        pendingSigningPublicKey: String,
        pendingEncryptionPublicKey: String,
    ): ByteArray = canonicalLines(
        listOf(
            PAIRING_FINGERPRINT_CONTEXT_VERSION,
            "userId=$userId",
            "approvingDeviceId=$approvingDeviceId",
            "approvingKeyVersion=$approvingKeyVersion",
            "approvingSigningPublicKey=$approvingSigningPublicKey",
            "approvingEncryptionPublicKey=$approvingEncryptionPublicKey",
            "pendingDeviceId=$pendingDeviceId",
            "pendingKeyVersion=$pendingKeyVersion",
            "pendingSigningPublicKey=$pendingSigningPublicKey",
            "pendingEncryptionPublicKey=$pendingEncryptionPublicKey",
        ),
    )

    /** SHA-256 of the context, first 12 bytes, upper-case hex in groups of four. */
    fun pairingFingerprint(context: ByteArray): String =
        sha256(context).copyOf(12)
            .joinToString("") { "%02X".format(it) }
            .chunked(4)
            .joinToString("-")

    fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)
}

/** Standard padded base64, rejecting non-canonical encodings like the extension. */
object B64 {
    fun encode(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes)

    fun decode(value: String): ByteArray {
        val bytes = Base64.getDecoder().decode(value)
        require(encode(bytes) == value) { "Non-canonical base64" }
        return bytes
    }

    fun decodeExact(value: String, length: Int): ByteArray {
        val bytes = decode(value)
        require(bytes.size == length) { "Expected $length bytes" }
        return bytes
    }

    fun isExact(value: String?, length: Int): Boolean =
        value != null && runCatching { decodeExact(value, length) }.isSuccess
}

/**
 * The offline recovery credential, in the extension's text format:
 *
 *     copyyt-recovery-v1
 *     rootDeviceId=<uuid>
 *     privateKeyPkcs8Base64=<PKCS#8 Ed25519 private key>
 */
object RecoveryCredential {
    const val FORMAT = "copyyt-recovery-v1"

    /** RFC 8410 PKCS#8 header for an Ed25519 private key; the 32-byte seed follows. */
    private val ED25519_PKCS8_PREFIX: ByteArray =
        "302e020100300506032b657004220420".chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private val UUID_PATTERN =
        Regex("^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", RegexOption.IGNORE_CASE)

    data class Parsed(val rootDeviceId: String, val seed: ByteArray)

    class InvalidCredentialException(message: String) : Exception(message)

    fun format(rootDeviceId: String, seed: ByteArray): String {
        require(seed.size == 32) { "Recovery seed must be 32 bytes" }
        return listOf(
            FORMAT,
            "rootDeviceId=$rootDeviceId",
            "privateKeyPkcs8Base64=${B64.encode(ED25519_PKCS8_PREFIX + seed)}",
        ).joinToString("\n")
    }

    /** Tolerates CRLF, surrounding blank lines and trailing spaces from saving/pasting. */
    fun parse(text: String): Parsed {
        val lines = text.replace(Regex("\r\n?"), "\n").trim().split("\n").map { it.trim() }
        if (lines.size != 3 || lines[0] != FORMAT) {
            throw InvalidCredentialException("The recovery credential format is invalid")
        }
        val rootDeviceId = lines[1].removePrefix("rootDeviceId=").takeIf { lines[1].startsWith("rootDeviceId=") }
        val keyText = lines[2].removePrefix("privateKeyPkcs8Base64=").takeIf { lines[2].startsWith("privateKeyPkcs8Base64=") }
        if (rootDeviceId == null || !UUID_PATTERN.matches(rootDeviceId) || keyText.isNullOrEmpty()) {
            throw InvalidCredentialException("The recovery credential fields are invalid")
        }
        val der = runCatching { B64.decode(keyText) }
            .getOrElse { throw InvalidCredentialException("The recovery private key encoding is invalid") }
        if (der.size != ED25519_PKCS8_PREFIX.size + 32 ||
            !der.copyOf(ED25519_PKCS8_PREFIX.size).contentEquals(ED25519_PKCS8_PREFIX)
        ) {
            throw InvalidCredentialException("The recovery private key is not an Ed25519 PKCS#8 key")
        }
        return Parsed(rootDeviceId, der.copyOfRange(ED25519_PKCS8_PREFIX.size, der.size))
    }
}
