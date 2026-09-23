package com.psami.copyyt

import com.psami.copyyt.crypto.CopyytCrypto
import com.psami.copyyt.crypto.CryptoProtocolException
import com.psami.copyyt.crypto.DeviceKeys
import com.psami.copyyt.crypto.Envelope
import com.psami.copyyt.crypto.EnvelopeRecipient
import com.psami.copyyt.crypto.VerifiedPeer
import com.psami.copyyt.protocol.B64
import com.psami.copyyt.protocol.Protocol
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Pins the Kotlin protocol to bytes produced by the extension's own crypto
 * (tools/protocol-fixture.ts). If this fails, Android and Chrome cannot talk.
 */
class ProtocolFixtureTest {
    private val fixture: JsonObject = Json.parseToJsonElement(
        javaClass.classLoader!!.getResource("protocol-fixture.json")!!.readText(),
    ).jsonObject

    private fun str(obj: JsonObject, key: String) = obj[key]!!.jsonPrimitive.content
    private val userId = str(fixture, "userId")
    private val chromeId = str(fixture, "chromeId")
    private val androidId = str(fixture, "androidId")
    private val canonical = fixture["canonical"]!!.jsonObject

    private fun keys(name: String): DeviceKeys {
        val obj = fixture[name]!!.jsonObject
        return DeviceKeys(
            signingSeed = B64.decode(str(obj["signing"]!!.jsonObject, "d")),
            encryptionPrivateKey = B64.decode(str(obj["encryption"]!!.jsonObject, "d")),
        )
    }

    private val chromeKeys = keys("chromeKeys")
    private val androidKeys = keys("androidKeys")
    private val chromePeer = VerifiedPeer(
        userId, chromeId, 1, chromeKeys.signingPublicKeyBase64, chromeKeys.encryptionPublicKeyBase64,
    )
    private val androidPeer = VerifiedPeer(
        userId, androidId, 1, androidKeys.signingPublicKeyBase64, androidKeys.encryptionPublicKeyBase64,
    )

    private fun envelope(): Envelope {
        val e = fixture["envelope"]!!.jsonObject
        return Envelope(
            itemId = str(e, "itemId"),
            sourceDeviceId = str(e, "sourceDeviceId"),
            sourceKeyVersion = e["sourceKeyVersion"]!!.jsonPrimitive.int,
            sourceSignature = str(e, "sourceSignature"),
            protocolVersion = e["protocolVersion"]!!.jsonPrimitive.int,
            contentType = str(e, "contentType"),
            ciphertext = str(e, "ciphertext"),
            nonce = str(e, "nonce"),
            recipients = e["recipients"]!!.jsonArray.map {
                val r = it.jsonObject
                EnvelopeRecipient(
                    str(r, "deviceId"), r["deviceKeyVersion"]!!.jsonPrimitive.int,
                    str(r, "wrapNonce"), str(r, "wrappedContentKey"),
                )
            },
            expiresAt = str(e, "expiresAt"),
        )
    }

    @Test
    fun derivesTheSamePublicKeysFromPrivateKeys() {
        val chrome = fixture["chromeKeys"]!!.jsonObject
        assertEquals(str(chrome["signing"]!!.jsonObject, "x"), chromeKeys.signingPublicKeyBase64)
        assertEquals(str(chrome["encryption"]!!.jsonObject, "x"), chromeKeys.encryptionPublicKeyBase64)
    }

    @Test
    fun canonicalMessagesMatchTheExtensionByteForByte() {
        val env = envelope()
        assertArrayEquals(
            B64.decode(str(canonical, "approval")),
            Protocol.deviceApprovalMessage(
                userId, chromeId, 1, androidId, 1,
                androidKeys.encryptionPublicKeyBase64, androidKeys.signingPublicKeyBase64,
            ),
        )
        val m = canonical["managementInput"]!!.jsonObject
        assertArrayEquals(
            B64.decode(str(canonical, "management")),
            Protocol.deviceManagementMessage(
                str(m, "action"), userId, androidId, 1, androidId, 1,
                m["timestamp"]!!.jsonPrimitive.long, str(m, "nonce"), str(m, "name"),
                str(m, "platform"), listOf("clipboard"), str(m, "appVersion"), null,
            ),
        )
        assertArrayEquals(
            B64.decode(str(canonical, "socketAuth")),
            Protocol.socketAuthMessage(userId, androidId, 1, "socket-123", "AQIDBA=="),
        )
        assertArrayEquals(
            B64.decode(str(canonical, "envelopeSignature")),
            Protocol.clipboardEnvelopeSignatureMessage(
                userId, 1, env.itemId, chromeId, 1, env.contentType,
                B64.decode(env.nonce), B64.decode(env.ciphertext), env.expiresAt,
            ),
        )
        assertArrayEquals(
            B64.decode(str(canonical, "keyWrap")),
            Protocol.keyWrapContext(userId, 1, env.itemId, chromeId, 1, androidId, 1),
        )
        assertArrayEquals(
            B64.decode(str(canonical, "payloadAad")),
            Protocol.payloadAad(userId, 1, env.itemId, chromeId, 1, "text/plain", str(fixture, "expiresAt")),
        )
        val context = Protocol.pairingFingerprintContext(
            userId, chromeId, 1, chromeKeys.signingPublicKeyBase64, chromeKeys.encryptionPublicKeyBase64,
            androidId, 1, androidKeys.signingPublicKeyBase64, androidKeys.encryptionPublicKeyBase64,
        )
        assertArrayEquals(B64.decode(str(canonical, "fingerprintContext")), context)
        assertEquals(str(fixture, "fingerprint"), Protocol.pairingFingerprint(context))
    }

    @Test
    fun recoveryMessageAndCredentialMatchTheExtension() {
        val r = canonical["recoveryInput"]!!.jsonObject
        assertArrayEquals(
            B64.decode(str(canonical, "recovery")),
            Protocol.deviceRecoveryMessage(
                str(r, "userId"), str(r, "rootDeviceId"), str(r, "deviceId"), str(r, "name"),
                str(r, "platform"), str(r, "encryptionPublicKey"), str(r, "signingPublicKey"),
                listOf("clipboard"), str(r, "appVersion"), r["timestamp"]!!.jsonPrimitive.long,
                str(r, "nonce"), str(r, "newRecoveryPublicKey"),
            ),
        )
        val credential = fixture["recoveryCredential"]!!.jsonObject
        val text = listOf(
            "copyyt-recovery-v1",
            "rootDeviceId=$chromeId",
            "privateKeyPkcs8Base64=${str(credential, "pkcs8")}",
        ).joinToString("\r\n") + "\r\n"
        val parsed = com.psami.copyyt.protocol.RecoveryCredential.parse(text)
        assertEquals(chromeId, parsed.rootDeviceId)
        assertEquals(str(credential, "seed"), B64.encode(parsed.seed))
        // Exporting the same seed reproduces the extension's exact PKCS#8 text.
        assertEquals(
            text.trim().replace("\r\n", "\n"),
            com.psami.copyyt.protocol.RecoveryCredential.format(chromeId, parsed.seed),
        )
        assertEquals(
            str(credential, "publicKey"),
            B64.encode(com.google.crypto.tink.subtle.Ed25519Sign.KeyPair.newKeyPairFromSeed(parsed.seed).publicKey),
        )
    }

    @Test
    fun decryptsAnEnvelopeTheExtensionEncrypted() {
        val plaintext = CopyytCrypto.decrypt(userId, androidId, 1, androidKeys, chromePeer, envelope())
        assertEquals(str(fixture, "plaintext"), plaintext.toString(Charsets.UTF_8))
    }

    @Test
    fun rejectsTamperedOrMisaddressedEnvelopes() {
        val env = envelope()
        val tamperedCiphertext = B64.decode(env.ciphertext).also { it[0] = (it[0].toInt() xor 1).toByte() }
        val cases = listOf(
            env.copy(ciphertext = B64.encode(tamperedCiphertext)),
            env.copy(expiresAt = "2026-09-23T12:00:01.000Z"),
            env.copy(contentType = "text/html"),
            env.copy(sourceKeyVersion = 2),
        )
        for (case in cases) {
            assertThrows { CopyytCrypto.decrypt(userId, androidId, 1, androidKeys, chromePeer, case) }
        }
        // Signed by Chrome but claimed to come from an unrelated verified peer.
        assertThrows { CopyytCrypto.decrypt(userId, androidId, 1, androidKeys, androidPeer.copy(deviceId = chromeId), env) }
        // Addressed to Android; a different local device must refuse it.
        assertThrows { CopyytCrypto.decrypt(userId, chromeId, 1, chromeKeys, chromePeer, env) }
    }

    @Test
    fun verifiesTheExtensionsDeviceApprovalSignature() {
        val signature = str(fixture, "approvalSignature")
        assertTrue(
            CopyytCrypto.verifyApproval(
                userId, chromePeer, androidId, 1,
                androidKeys.encryptionPublicKeyBase64, androidKeys.signingPublicKeyBase64, signature,
            ),
        )
        assertFalse(
            CopyytCrypto.verifyApproval(
                userId, chromePeer, androidId, 2,
                androidKeys.encryptionPublicKeyBase64, androidKeys.signingPublicKeyBase64, signature,
            ),
        )
    }

    /** Writes an Android-encrypted envelope for `tools/protocol-fixture.ts verify`. */
    @Test
    fun encryptsAnEnvelopeForTheExtension() {
        val envelope = CopyytCrypto.encryptText(
            userId, androidId, 1, androidKeys,
            "from android ✅".toByteArray(Charsets.UTF_8), "text/plain",
            "2026-09-23T12:00:00Z", listOf(chromePeer),
        )
        assertEquals("2026-09-23T12:00:00.000Z", envelope.expiresAt)
        // Round-trips through the Kotlin decrypt path as the recipient.
        val roundTrip = CopyytCrypto.decrypt(userId, chromeId, 1, chromeKeys, androidPeer, envelope)
        assertEquals("from android ✅", roundTrip.toString(Charsets.UTF_8))
        val out = File("build/android-envelope.json")
        out.parentFile?.mkdirs()
        out.writeText(
            Json.encodeToString(
                JsonObject.serializer(),
                kotlinx.serialization.json.buildJsonObject {
                    put("itemId", kotlinx.serialization.json.JsonPrimitive(envelope.itemId))
                    put("sourceDeviceId", kotlinx.serialization.json.JsonPrimitive(envelope.sourceDeviceId))
                    put("sourceKeyVersion", kotlinx.serialization.json.JsonPrimitive(envelope.sourceKeyVersion))
                    put("sourceSignature", kotlinx.serialization.json.JsonPrimitive(envelope.sourceSignature))
                    put("protocolVersion", kotlinx.serialization.json.JsonPrimitive(envelope.protocolVersion))
                    put("contentType", kotlinx.serialization.json.JsonPrimitive(envelope.contentType))
                    put("ciphertext", kotlinx.serialization.json.JsonPrimitive(envelope.ciphertext))
                    put("nonce", kotlinx.serialization.json.JsonPrimitive(envelope.nonce))
                    put("expiresAt", kotlinx.serialization.json.JsonPrimitive(envelope.expiresAt))
                    put(
                        "recipients",
                        kotlinx.serialization.json.JsonArray(
                            envelope.recipients.map { r ->
                                kotlinx.serialization.json.buildJsonObject {
                                    put("deviceId", kotlinx.serialization.json.JsonPrimitive(r.deviceId))
                                    put("deviceKeyVersion", kotlinx.serialization.json.JsonPrimitive(r.deviceKeyVersion))
                                    put("wrapNonce", kotlinx.serialization.json.JsonPrimitive(r.wrapNonce))
                                    put("wrappedContentKey", kotlinx.serialization.json.JsonPrimitive(r.wrappedContentKey))
                                }
                            },
                        ),
                    )
                },
            ),
        )
    }

    private fun assertThrows(block: () -> Unit) {
        try {
            block()
        } catch (_: CryptoProtocolException) {
            return
        }
        throw AssertionError("Expected CryptoProtocolException")
    }
}
