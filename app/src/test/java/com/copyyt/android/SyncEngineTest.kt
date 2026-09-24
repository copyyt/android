package com.copyyt.android

import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.async
import com.copyyt.android.store.PreferencesStore
import com.copyyt.android.crypto.CopyytCrypto
import com.copyyt.android.crypto.DeviceKeys
import com.copyyt.android.crypto.Envelope
import com.copyyt.android.crypto.EnvelopeRecipient
import com.copyyt.android.crypto.VerifiedPeer
import com.google.crypto.tink.subtle.Ed25519Sign
import com.copyyt.android.net.ApiException
import com.copyyt.android.net.ApproveDeviceRequest
import com.copyyt.android.net.DeviceManagementRequest
import com.copyyt.android.net.RecoverDeviceRequest
import com.copyyt.android.protocol.RecoveryCredential
import com.copyyt.android.net.BackendApi
import com.copyyt.android.net.ClipboardItemDto
import com.copyyt.android.net.CopyytJson
import com.copyyt.android.net.DeviceDto
import com.copyyt.android.net.RecipientDto
import com.copyyt.android.net.RegisterDeviceRequest
import com.copyyt.android.net.SignInResponse
import com.copyyt.android.net.UserDto
import com.copyyt.android.protocol.B64
import com.copyyt.android.protocol.Protocol
import com.copyyt.android.store.IdentityStore
import com.copyyt.android.store.InMemoryStorage
import com.copyyt.android.store.ProcessedItems
import com.copyyt.android.store.Session
import com.copyyt.android.store.SessionStore
import com.copyyt.android.sync.SocketConnection
import com.copyyt.android.sync.SocketListener
import com.copyyt.android.sync.AccountInfo
import com.copyyt.android.sync.SyncEngine
import com.copyyt.android.net.PlanLimitsDto
import com.copyyt.android.net.PlanDto
import com.copyyt.android.sync.ClipboardBundle
import com.copyyt.android.sync.ClipContent
import com.copyyt.android.sync.SyncException
import com.copyyt.android.sync.SyncPlatform
import com.copyyt.android.sync.SyncState
import com.copyyt.android.trust.TrustStore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.Instant
import java.util.Base64

private const val USER_ID = "507f1f77bcf86cd799439011"
private const val OTHER_USER_ID = "other-user"
private const val OTHER_ACCOUNT_TOKEN = "other-account"
private const val CHROME_ID = "00000000-0000-4000-8000-000000000001"
private const val OTHER_ID = "00000000-0000-4000-8000-000000000003"

/** Enough of the backend to drive registration, pairing and relay delivery. */
private class FakeBackend(private val root: DeviceKeys) : BackendApi {
    val devices = linkedMapOf<String, DeviceDto>()
    val registrations = mutableListOf<RegisterDeviceRequest>()
    val revoked = mutableSetOf<String>()
    val revokeRequests = mutableListOf<Pair<String, DeviceManagementRequest>>()
    val recoverRequests = mutableListOf<RecoverDeviceRequest>()
    var latest: ClipboardItemDto? = null
    /** Public key of the account's offline recovery credential, if any. */
    var anchorRecoveryKey: String? = null
    val chromeRecoverySeed: ByteArray = Ed25519Sign.KeyPair.newKeyPair().privateKey
    /** The account the fake is serving; the other account has no devices. */
    var signedInUser = USER_ID

    fun addRoot() {
        devices[CHROME_ID] = device(CHROME_ID, "Chrome on laptop", "chrome", root, "trusted", listOf("clipboard"))
        anchorRecoveryKey = B64.encode(Ed25519Sign.KeyPair.newKeyPairFromSeed(chromeRecoverySeed).publicKey)
    }

    private fun verify(signingKey: String, message: ByteArray, signature: String) {
        check(CopyytCrypto.verify(B64.decode(signingKey), message, B64.decode(signature))) { "bad signature" }
    }

    fun device(id: String, name: String, platform: String, keys: DeviceKeys, trust: String, caps: List<String>) =
        DeviceDto(id, name, platform, keys.encryptionPublicKeyBase64, keys.signingPublicKeyBase64, trust, 1, caps)

    /** What the Chrome root does after the user types the fingerprint. */
    fun approve(deviceId: String) {
        val pending = devices[deviceId]!!
        val signature = root.sign(
            Protocol.deviceApprovalMessage(
                USER_ID, CHROME_ID, 1, pending.deviceId, pending.keyVersion,
                pending.encryptionPublicKey, pending.signingPublicKey,
            ),
        )
        devices[deviceId] = pending.copy(
            trustState = "trusted", approvedByDeviceId = CHROME_ID, approvalSignature = B64.encode(signature),
        )
    }

    override fun signInPasswordless(email: String) = Unit
    override fun verifyEmail(email: String, code: Int, name: String?) = error("unused")
    override fun refreshTokens(refreshToken: String): SignInResponse =
        SignInResponse(jwt(), "refresh-2", UserDto(signedInUser, "me@example.com"))
    override fun logout(refreshToken: String) = Unit

    override fun registerDevice(token: String, request: RegisterDeviceRequest): DeviceDto {
        registrations += request
        if (request.deviceId in revoked) throw ApiException(409, "device_revoked", "Revoked devices cannot be reactivated")
        val existing = devices[request.deviceId]
        if (existing != null) {
            return existing.copy(recoveryKeyActive = request.recoveryPublicKey != null && request.recoveryPublicKey == anchorRecoveryKey)
        }
        val firstDevice = devices.values.none { it.trustState == "trusted" } && anchorRecoveryKey == null
        if (firstDevice && request.recoveryPublicKey == null) {
            throw ApiException(400, "recovery_public_key_required", "first device needs a recovery key")
        }
        if (firstDevice) anchorRecoveryKey = request.recoveryPublicKey
        return DeviceDto(
            request.deviceId, request.name, request.platform, request.encryptionPublicKey,
            request.signingPublicKey, if (firstDevice) "trusted" else "pending", 1, request.capabilities,
        ).also { devices[it.deviceId] = it }.copy(recoveryKeyActive = firstDevice)
    }

    override fun listTrusted(token: String) =
        if (signedInUser != USER_ID) emptyList() else devices.values.filter { it.trustState == "trusted" }
    override fun listPending(token: String) =
        if (signedInUser != USER_ID) emptyList() else devices.values.filter { it.trustState == "pending" }
    override fun latestItem(token: String, deviceId: String) = latest
    override fun googleSignIn(idToken: String): SignInResponse {
        signedInUser = if (idToken == OTHER_ACCOUNT_TOKEN) OTHER_USER_ID else USER_ID
        val email = if (signedInUser == USER_ID) "me@example.com" else "other@example.com"
        return SignInResponse(jwt(), "refresh-google", UserDto(signedInUser, email))
    }

    override fun approveDevice(token: String, request: ApproveDeviceRequest): DeviceDto {
        val approver = devices[request.approvingDeviceId]!!
        val pending = devices[request.pendingDeviceId]!!
        verify(
            approver.signingPublicKey,
            Protocol.deviceApprovalMessage(
                USER_ID, approver.deviceId, approver.keyVersion, pending.deviceId, pending.keyVersion,
                pending.encryptionPublicKey, pending.signingPublicKey,
            ),
            request.approvalSignature,
        )
        return pending.copy(
            trustState = "trusted", approvedByDeviceId = approver.deviceId, approvalSignature = request.approvalSignature,
        ).also { devices[it.deviceId] = it }
    }

    override fun revokeDevice(token: String, deviceId: String, request: DeviceManagementRequest): DeviceDto {
        val requester = devices[request.requestingDeviceId]!!
        val target = devices[deviceId]!!
        verify(
            requester.signingPublicKey,
            Protocol.deviceManagementMessage(
                "revoke", USER_ID, requester.deviceId, request.requestingKeyVersion, target.deviceId,
                target.keyVersion, request.timestamp, request.nonce, null, null, null, null, null,
            ),
            request.signature,
        )
        revokeRequests += deviceId to request
        revoked += deviceId
        devices.remove(deviceId)
        return target.copy(trustState = "revoked")
    }

    override fun recoverDevice(token: String, request: RecoverDeviceRequest): DeviceDto {
        recoverRequests += request
        verify(
            anchorRecoveryKey!!,
            Protocol.deviceRecoveryMessage(
                USER_ID, request.rootDeviceId, request.deviceId, request.name, request.platform,
                request.encryptionPublicKey, request.signingPublicKey, request.capabilities,
                request.appVersion, request.timestamp, request.nonce, request.newRecoveryPublicKey,
            ),
            request.signature,
        )
        check(devices.values.none { it.trustState == "trusted" && it.approvedByDeviceId == null }) { "root active" }
        anchorRecoveryKey = request.newRecoveryPublicKey
        return devices[request.deviceId]!!.copy(trustState = "trusted", approvedByDeviceId = null, approvalSignature = null)
            .also { devices[it.deviceId] = it }
            .copy(recoveryKeyRotated = true)
    }

    override fun requestAccountResetCode(token: String) = Unit

    override fun resetAccount(token: String, code: Int) {
        check(code == 123456)
        revoked += devices.keys
        devices.clear()
        anchorRecoveryKey = null
    }

    var accountDeleted = false

    override fun requestAccountDeletionCode(token: String) = Unit

    val profileNames = mutableListOf<String>()

    /** Null mimics a backend without plans. */
    var plan: PlanDto? = null

    override fun getPlan(token: String): PlanDto? = plan

    override fun updateProfile(token: String, name: String): UserDto {
        profileNames += name
        return UserDto(signedInUser, if (signedInUser == USER_ID) "me@example.com" else "other@example.com", name)
    }

    override fun deleteAccount(token: String, code: Int) {
        if (code != 123456) throw ApiException(401, "invalid_or_expired_otp", "The deletion code is invalid or has expired")
        accountDeleted = true
        devices.clear()
    }
}

private class FakeSocket : SocketConnection {
    val deviceAuth = mutableListOf<JsonObject>()
    val published = mutableListOf<JsonObject>()
    var closed = false
    override fun close() { closed = true }
    override fun emitDeviceAuth(payload: JsonObject) { deviceAuth += payload }
    override fun publish(payload: JsonObject, onAck: (JsonObject?) -> Unit) {
        published += payload
        onAck(JsonObject(mapOf("accepted" to JsonPrimitive(true), "itemId" to payload["itemId"]!!)))
    }
}

private class FakePlatform : SyncPlatform {
    val clipboard = mutableListOf<String>()
    val clips = mutableListOf<ClipContent>()
    override val deviceName = "Android · Test Pixel"
    override val appVersion = "0.1.0"
    override fun now(): Instant = Instant.now()
    override fun writeClipboard(content: ClipContent) {
        clips += content
        content.text?.let { clipboard += it }
    }
    override fun notifyReceived(sourceName: String, content: ClipContent) = Unit
}

private fun jwt(): String {
    val enc = Base64.getUrlEncoder().withoutPadding()
    val payload = """{"sub":"$USER_ID","exp":${Instant.now().plusSeconds(3600).epochSecond}}"""
    return "${enc.encodeToString("{}".toByteArray())}.${enc.encodeToString(payload.toByteArray())}.sig"
}

class SyncEngineTest {
    private val chromeKeys = DeviceKeys.generate()
    private val backend = FakeBackend(chromeKeys)
    private val platform = FakePlatform()
    private val storage = InMemoryStorage()
    private val identities = IdentityStore(storage)
    private var socket: FakeSocket? = null
    private var listener: SocketListener? = null

    private fun engine(scope: CoroutineScope): SyncEngine {
        SessionStore(storage).set(Session(jwt(), "refresh-1", USER_ID, "me@example.com"))
        return SyncEngine(
            api = backend,
            socketUrl = "https://socket.example",
            socketFactory = { _, _, l -> listener = l; FakeSocket().also { socket = it } },
            sessions = SessionStore(storage),
            identities = identities,
            trust = TrustStore(storage),
            processed = ProcessedItems(storage),
            platform = platform,
            scope = scope,
        )
    }

    private fun androidId() = identities.get(USER_ID)!!.deviceId
    private fun androidPeer(): VerifiedPeer {
        val id = identities.get(USER_ID)!!
        return VerifiedPeer(USER_ID, id.deviceId, 1, id.keys.signingPublicKeyBase64, id.keys.encryptionPublicKeyBase64)
    }
    private val chromePeer get() = VerifiedPeer(
        USER_ID, CHROME_ID, 1, chromeKeys.signingPublicKeyBase64, chromeKeys.encryptionPublicKeyBase64,
    )

    /** The fingerprint the Chrome root computes and displays for the pending phone. */
    private fun chromeFingerprint(): String {
        val pending = backend.devices[androidId()]!!
        return Protocol.pairingFingerprint(
            Protocol.pairingFingerprintContext(
                USER_ID, CHROME_ID, 1, chromeKeys.signingPublicKeyBase64, chromeKeys.encryptionPublicKeyBase64,
                pending.deviceId, 1, pending.signingPublicKey, pending.encryptionPublicKey,
            ),
        )
    }

    private suspend fun pairedAndConnected(engine: SyncEngine) {
        backend.addRoot()
        engine.refresh()
        engine.confirmPairing()
        backend.approve(androidId())
        engine.refresh()
        listener!!.onReady()
    }

    private fun itemFromChrome(text: String, expiresAt: Instant = Instant.now().plusSeconds(60)): ClipboardItemDto =
        itemFromChrome(text.toByteArray(), "text/plain", expiresAt)

    private fun itemFromChrome(
        bytes: ByteArray,
        contentType: String,
        expiresAt: Instant = Instant.now().plusSeconds(60),
    ): ClipboardItemDto {
        val env = CopyytCrypto.encryptText(
            USER_ID, CHROME_ID, 1, chromeKeys, bytes, contentType,
            Protocol.canonicalExpiry(expiresAt), listOf(androidPeer()),
        )
        return ClipboardItemDto(
            env.itemId, env.sourceDeviceId, env.sourceKeyVersion, env.sourceSignature, env.protocolVersion,
            env.contentType, env.ciphertext, env.nonce,
            env.recipients.map { RecipientDto(it.deviceId, it.deviceKeyVersion, it.wrapNonce, it.wrappedContentKey) },
            env.expiresAt,
        )
    }

    @Test
    fun refusesToBecomeTheAccountRoot() = runTest {
        val engine = engine(backgroundScope)
        engine.refresh()
        assertEquals(SyncState.NoRoot(canBeFirstDevice = true), engine.state.value)
        assertTrue("becoming the root must be an explicit choice", backend.registrations.isEmpty())
    }

    @Test
    fun pairsWithTheChromeRootUsingTheSameFingerprint() = runTest {
        val engine = engine(backgroundScope)
        backend.addRoot()
        engine.refresh()
        val pairing = engine.state.value as SyncState.Pairing
        assertEquals(chromeFingerprint(), pairing.fingerprint)
        assertEquals("Chrome on laptop", pairing.rootName)
        assertEquals("android", backend.devices[androidId()]!!.platform)

        engine.confirmPairing()
        val waiting = engine.state.value as SyncState.WaitingForApproval
        assertEquals(chromeFingerprint(), waiting.fingerprint)

        backend.approve(androidId())
        engine.refresh()
        assertTrue(engine.state.value is SyncState.Ready)

        // Socket device auth signs the server challenge with the phone's key.
        listener!!.onChallenge("socket-1", "Y2hhbGxlbmdl")
        val auth = socket!!.deviceAuth.single()
        val identity = identities.get(USER_ID)!!
        assertTrue(
            CopyytCrypto.verify(
                identity.keys.signingPublicKey,
                Protocol.socketAuthMessage(USER_ID, identity.deviceId, 1, "socket-1", "Y2hhbGxlbmdl"),
                B64.decode(auth["signature"]!!.jsonPrimitive.content),
            ),
        )
        listener!!.onReady()
        assertEquals(true, (engine.state.value as SyncState.Ready).connected)
    }

    @Test
    fun rejectsAnApprovalNotSignedByThePinnedRoot() = runTest {
        val engine = engine(backgroundScope)
        backend.addRoot()
        engine.refresh()
        engine.confirmPairing()
        val forged = DeviceKeys.generate().sign("x".toByteArray())
        backend.devices[androidId()] = backend.devices[androidId()]!!.copy(
            trustState = "trusted", approvedByDeviceId = CHROME_ID, approvalSignature = B64.encode(forged),
        )
        engine.refresh()
        assertTrue(engine.state.value is SyncState.Error)
        assertEquals(null, socket)
    }

    @Test
    fun resignsMetadataOnReRegistration() = runTest {
        val engine = engine(backgroundScope)
        backend.addRoot()
        engine.refresh()
        engine.refresh()
        val second = backend.registrations.last()
        val identity = identities.get(USER_ID)!!
        val message = Protocol.deviceManagementMessage(
            "update", USER_ID, identity.deviceId, 1, identity.deviceId, 1,
            second.managementTimestamp!!, second.managementNonce!!, second.name, "android",
            SyncEngine.CAPABILITIES, "0.1.0", null,
        )
        assertTrue(
            CopyytCrypto.verify(identity.keys.signingPublicKey, message, B64.decode(second.managementSignature!!)),
        )
        assertEquals(null, backend.registrations.first().managementSignature)
    }

    @Test
    fun receivesTextOnceAndIgnoresReplaysExpiryAndUnverifiedSources() = runTest {
        val engine = engine(backgroundScope)
        pairedAndConnected(engine)

        val item = itemFromChrome("hello from chrome")
        engine.receive(item)
        engine.receive(item)
        assertEquals(listOf("hello from chrome"), platform.clipboard)

        engine.receive(itemFromChrome("stale", Instant.now().minusSeconds(1)))
        engine.receive(itemFromChrome("too far", Instant.now().plusSeconds(3600)))

        // A pending device the root never approved is not a trusted source.
        val stranger = DeviceKeys.generate()
        backend.devices[OTHER_ID] = backend.device(OTHER_ID, "Stranger", "chrome", stranger, "pending", listOf("clipboard"))
        val env = CopyytCrypto.encryptText(
            USER_ID, OTHER_ID, 1, stranger, "evil".toByteArray(), "text/plain",
            Protocol.canonicalExpiry(Instant.now().plusSeconds(60)), listOf(androidPeer()),
        )
        engine.receive(
            CopyytJson.decodeFromString(
                ClipboardItemDto.serializer(),
                CopyytJson.encodeToString(ClipboardItemDto.serializer(), itemFromChrome("x").copy(
                    itemId = env.itemId, sourceDeviceId = OTHER_ID, sourceSignature = env.sourceSignature,
                    ciphertext = env.ciphertext, nonce = env.nonce, expiresAt = env.expiresAt,
                    recipients = env.recipients.map { RecipientDto(it.deviceId, it.deviceKeyVersion, it.wrapNonce, it.wrappedContentKey) },
                )),
            ),
        )
        assertEquals(listOf("hello from chrome"), platform.clipboard)
    }

    @Test
    fun trustsASecondDeviceApprovedByTheRoot() = runTest {
        val engine = engine(backgroundScope)
        pairedAndConnected(engine)
        val laptop = DeviceKeys.generate()
        backend.devices[OTHER_ID] = backend.device(OTHER_ID, "Chrome on desktop", "chrome", laptop, "pending", listOf("clipboard"))
        backend.approve(OTHER_ID)
        val env = CopyytCrypto.encryptText(
            USER_ID, OTHER_ID, 1, laptop, "from desktop".toByteArray(), "text/plain",
            Protocol.canonicalExpiry(Instant.now().plusSeconds(60)), listOf(androidPeer()),
        )
        engine.receive(
            ClipboardItemDto(
                env.itemId, env.sourceDeviceId, 1, env.sourceSignature, 1, env.contentType, env.ciphertext,
                env.nonce, env.recipients.map { RecipientDto(it.deviceId, it.deviceKeyVersion, it.wrapNonce, it.wrappedContentKey) },
                env.expiresAt,
            ),
        )
        assertEquals(listOf("from desktop"), platform.clipboard)
    }

    private val png = byteArrayOf(0x89.toByte(), 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3)

    /** Makes the paired Chrome root advertise image and rich-text support. */
    private suspend fun chromeReceivesImages(engine: SyncEngine) {
        backend.devices[CHROME_ID] = backend.devices[CHROME_ID]!!.copy(
            capabilities = listOf("clipboard", "clipboard-bundle-v1", "clipboard-html-v1", "clipboard-image-png-assisted-write-v1"),
        )
        engine.refresh()
        listener!!.onReady()
    }

    private fun decryptPublished(index: Int = 0): Pair<String, ByteArray> {
        val dto = CopyytJson.decodeFromJsonElement(ClipboardItemDto.serializer(), socket!!.published[index])
        val plaintext = CopyytCrypto.decrypt(
            USER_ID, CHROME_ID, 1, chromeKeys, androidPeer(),
            Envelope(
                dto.itemId, dto.sourceDeviceId, dto.sourceKeyVersion, dto.sourceSignature, dto.protocolVersion,
                dto.contentType, dto.ciphertext, dto.nonce,
                dto.recipients.map { EnvelopeRecipient(it.deviceId, it.deviceKeyVersion, it.wrapNonce, it.wrappedContentKey) },
                dto.expiresAt,
            ),
        )
        return dto.contentType to plaintext
    }

    @Test
    fun anImageFromChromeLandsOnTheClipboard() = runTest {
        val engine = engine(backgroundScope)
        pairedAndConnected(engine)
        val bundle = ClipboardBundle.encode(ClipContent(text = "caption", html = "<b>caption</b>", png = png))
        engine.receive(itemFromChrome(bundle, ClipboardBundle.MIME))

        val clip = platform.clips.single()
        assertTrue(clip.png!!.contentEquals(png))
        assertEquals("caption", clip.text)
        assertEquals("<b>caption</b>", clip.html)
    }

    @Test
    fun aMalformedBundleIsIgnored() = runTest {
        val engine = engine(backgroundScope)
        pairedAndConnected(engine)
        val bad = """{"version":1,"representations":[{"mime":"text/html","encoding":"utf-8","data":"x"}]}"""
        engine.receive(itemFromChrome(bad.toByteArray(), ClipboardBundle.MIME))
        assertTrue(platform.clips.isEmpty())
    }

    @Test
    fun anImageIsSentAsABundleToImageCapableDevices() = runTest {
        val engine = engine(backgroundScope)
        pairedAndConnected(engine)
        chromeReceivesImages(engine)

        assertEquals(1, engine.sendClip(ClipContent(png = png)))
        val (contentType, plaintext) = decryptPublished()
        assertEquals(ClipboardBundle.MIME, contentType)
        assertTrue(ClipboardBundle.decode(plaintext).png!!.contentEquals(png))
    }

    @Test
    fun textOnlyDevicesGetPlainTextAndImageOnlyClipsSkipThem() = runTest {
        val engine = engine(backgroundScope)
        pairedAndConnected(engine)
        // The paired Chrome root still advertises only plain text.
        engine.sendClip(ClipContent(text = "caption", html = "<b>caption</b>", png = png))
        val (contentType, plaintext) = decryptPublished()
        assertEquals("text/plain", contentType)
        assertEquals("caption", plaintext.toString(Charsets.UTF_8))

        val failure = runCatching { engine.sendClip(ClipContent(png = png)) }.exceptionOrNull()
        assertTrue(failure is SyncException)
    }

    @Test
    fun theFreePlanDropsImagesButKeepsTheirText() = runTest {
        val engine = engine(backgroundScope)
        pairedAndConnected(engine)
        chromeReceivesImages(engine)
        backend.plan = PlanDto("free", PlanLimitsDto(images = false, directTransfer = false, maxDevices = 2))

        engine.sendClip(ClipContent(text = "caption", png = png))
        val (_, plaintext) = decryptPublished()
        assertEquals("caption", plaintext.toString(Charsets.UTF_8))

        val failure = runCatching { engine.sendClip(ClipContent(png = png)) }.exceptionOrNull()
        assertTrue(failure is SyncException && failure.message!!.contains("Pro"))
        assertEquals(1, socket!!.published.size)
    }

    @Test
    fun sendsOnlyToVerifiedTextCapablePeers() = runTest {
        val engine = engine(backgroundScope)
        pairedAndConnected(engine)
        // A pending (unapproved) device must never receive a wrapped key.
        backend.devices[OTHER_ID] = backend.device(
            OTHER_ID, "Pending", "chrome", DeviceKeys.generate(), "pending", listOf("clipboard"),
        )
        engine.refresh()
        listener!!.onReady()

        assertEquals(1, engine.sendText("from phone"))
        val payload = socket!!.published.single()
        val dto = CopyytJson.decodeFromJsonElement(ClipboardItemDto.serializer(), payload)
        assertEquals(listOf(CHROME_ID), dto.recipients.map { it.deviceId })
        val plaintext = CopyytCrypto.decrypt(
            USER_ID, CHROME_ID, 1, chromeKeys, androidPeer(),
            Envelope(
                dto.itemId, dto.sourceDeviceId, dto.sourceKeyVersion, dto.sourceSignature, dto.protocolVersion,
                dto.contentType, dto.ciphertext, dto.nonce,
                dto.recipients.map { EnvelopeRecipient(it.deviceId, it.deviceKeyVersion, it.wrapNonce, it.wrappedContentKey) },
                dto.expiresAt,
            ),
        )
        assertEquals("from phone", plaintext.toString(Charsets.UTF_8))
        // Exactly the backend's whitelisted DTO fields; forbidNonWhitelisted rejects extras.
        assertEquals(
            setOf("itemId", "sourceDeviceId", "sourceKeyVersion", "sourceSignature", "protocolVersion",
                "contentType", "ciphertext", "nonce", "recipients", "expiresAt"),
            payload.keys,
        )
        assertNotNull(androidId())
    }

    @Test
    fun sendReReadsMembershipSoRemovedDevicesAreSkippedAndNewOnesIncluded() = runTest {
        val engine = engine(backgroundScope)
        pairedAndConnected(engine)
        val desktop = DeviceKeys.generate()
        backend.devices[OTHER_ID] = backend.device(OTHER_ID, "Chrome on desktop", "chrome", desktop, "pending", listOf("clipboard"))
        backend.approve(OTHER_ID)

        engine.sendText("one")
        val first = CopyytJson.decodeFromJsonElement(ClipboardItemDto.serializer(), socket!!.published.last())
        assertEquals(setOf(CHROME_ID, OTHER_ID), first.recipients.map { it.deviceId }.toSet())

        backend.devices.remove(OTHER_ID) // revoked devices vanish from the trusted list
        engine.sendText("two")
        val second = CopyytJson.decodeFromJsonElement(ClipboardItemDto.serializer(), socket!!.published.last())
        assertEquals(listOf(CHROME_ID), second.recipients.map { it.deviceId })
    }

    @Test
    fun aRemovedPhoneCanBeSetUpAgainAsANewPendingDevice() = runTest {
        val engine = engine(backgroundScope)
        pairedAndConnected(engine)
        val oldId = androidId()
        backend.revoked += oldId
        backend.devices.remove(oldId)
        engine.refresh()
        assertEquals(SyncState.Revoked, engine.state.value)

        engine.setUpAgain()
        val pairing = engine.state.value as SyncState.Pairing
        assertTrue("a new identity is created", androidId() != oldId)
        assertEquals("pending", backend.devices[androidId()]!!.trustState)
        assertEquals(chromeFingerprint(), pairing.fingerprint)
    }

    @Test
    fun signingOutOfARemovedPhoneStartsFreshOnTheNextSignIn() = runTest {
        val engine = engine(backgroundScope)
        pairedAndConnected(engine)
        val oldId = androidId()
        backend.revoked += oldId
        backend.devices.remove(oldId)
        engine.refresh()
        engine.signOut()

        SessionStore(storage).set(Session(jwt(), "refresh-3", USER_ID, "me@example.com"))
        engine.refresh()
        assertTrue(engine.state.value is SyncState.Pairing)
        assertTrue(androidId() != oldId)
    }

    // ---- Android as the account root ------------------------------------

    private suspend fun phoneAsRoot(engine: SyncEngine) {
        engine.refresh()
        engine.setUpAsFirstDevice()
        listener!!.onReady()
    }

    @Test
    fun aPhoneCanBecomeTheFirstDeviceAndRoot() = runTest {
        val engine = engine(backgroundScope)
        phoneAsRoot(engine)

        val ready = engine.state.value as SyncState.Ready
        assertTrue(ready.isRoot)
        assertEquals(true, ready.recovery?.exportable)
        val first = backend.registrations.first { it.recoveryPublicKey != null }
        assertEquals(backend.anchorRecoveryKey, first.recoveryPublicKey)
    }

    @Test
    fun theRootPhoneExportsARecoveryCredentialAndDeletesItOnceSaved() = runTest {
        val engine = engine(backgroundScope)
        phoneAsRoot(engine)
        val credential = engine.exportRecoveryCredential()
        val parsed = RecoveryCredential.parse(credential)
        assertEquals(androidId(), parsed.rootDeviceId)
        assertEquals(
            backend.anchorRecoveryKey,
            B64.encode(Ed25519Sign.KeyPair.newKeyPairFromSeed(parsed.seed).publicKey),
        )

        engine.confirmRecoverySaved()
        assertEquals(null, identities.get(USER_ID)!!.recoverySeed)
        assertEquals(RecoveryStatusExported, (engine.state.value as SyncState.Ready).recovery)
        assertThrowsSync { engine.exportRecoveryCredential() }
    }

    @Test
    fun theRootPhoneApprovesAChromeDeviceOnlyWithTheMatchingCode() = runTest {
        val engine = engine(backgroundScope)
        phoneAsRoot(engine)
        val laptop = DeviceKeys.generate()
        backend.devices[OTHER_ID] = backend.device(OTHER_ID, "Chrome on desktop", "chrome", laptop, "pending", listOf("clipboard"))
        engine.refresh()

        val approval = (engine.state.value as SyncState.Ready).pendingApprovals.single()
        // What the pending Chrome shows: fingerprint over (phone root, pending Chrome).
        val phone = identities.get(USER_ID)!!
        val expected = Protocol.pairingFingerprint(
            Protocol.pairingFingerprintContext(
                USER_ID, phone.deviceId, 1, phone.keys.signingPublicKeyBase64, phone.keys.encryptionPublicKeyBase64,
                OTHER_ID, 1, laptop.signingPublicKeyBase64, laptop.encryptionPublicKeyBase64,
            ),
        )
        assertEquals(expected, approval.fingerprint)

        assertThrowsSync { engine.approveDevice(OTHER_ID, "0000-0000-0000-0000-0000-0000") }
        assertEquals("pending", backend.devices[OTHER_ID]!!.trustState)

        engine.approveDevice(OTHER_ID, expected.lowercase().replace("-", " "))
        assertEquals("trusted", backend.devices[OTHER_ID]!!.trustState)
        val ready = engine.state.value as SyncState.Ready
        assertTrue(ready.pendingApprovals.isEmpty())
        assertTrue(ready.peers.single { it.deviceId == OTHER_ID }.trusted)
        assertEquals(1, engine.sendText("to the new laptop"))
    }

    @Test
    fun aPairedPhoneRemovesAnotherDeviceWithASignedRequest() = runTest {
        val engine = engine(backgroundScope)
        pairedAndConnected(engine)
        backend.devices[OTHER_ID] = backend.device(OTHER_ID, "Old laptop", "chrome", DeviceKeys.generate(), "pending", listOf("clipboard"))
        engine.refresh()

        engine.removeDevice(OTHER_ID)
        assertEquals(OTHER_ID, backend.revokeRequests.single().first)
        assertTrue((engine.state.value as SyncState.Ready).peers.none { it.deviceId == OTHER_ID })
        assertThrowsSync { engine.removeDevice(androidId()) }
    }

    @Test
    fun aPairedPhoneBecomesTheRootWithTheRecoveryCredentialAfterTheRootIsRemoved() = runTest {
        val engine = engine(backgroundScope)
        pairedAndConnected(engine)
        engine.removeDevice(CHROME_ID)
        val afterRemoval = engine.state.value as SyncState.Ready
        assertTrue(afterRemoval.rootMissing)

        val credential = RecoveryCredential.format(CHROME_ID, backend.chromeRecoverySeed)
        engine.recoverAsRoot("  $credential\r\n")

        val ready = engine.state.value as SyncState.Ready
        assertTrue(ready.isRoot)
        assertTrue(!ready.rootMissing)
        val request = backend.recoverRequests.single()
        assertEquals(androidId(), request.deviceId)
        // The rotated key is this phone's new exportable credential.
        assertEquals(backend.anchorRecoveryKey, identities.get(USER_ID)!!.recoveryPublicKey)
        assertEquals(true, ready.recovery?.exportable)
    }

    @Test
    fun anAccountResetLetsThePhoneStartOverAsTheFirstDevice() = runTest {
        val engine = engine(backgroundScope)
        pairedAndConnected(engine)
        val oldId = androidId()
        engine.resetAccount(123456)
        assertEquals(SyncState.NoRoot(canBeFirstDevice = true), engine.state.value)

        engine.setUpAsFirstDevice()
        assertTrue((engine.state.value as SyncState.Ready).isRoot)
        assertTrue(androidId() != oldId)
    }

    @Test
    fun accountDeletionSignsOutAndForgetsThePhone() = runTest {
        val engine = engine(backgroundScope)
        pairedAndConnected(engine)
        engine.deleteAccount(123456)

        assertTrue(backend.accountDeleted)
        assertEquals(SyncState.SignedOut, engine.state.value)
        assertEquals(null, SessionStore(storage).get())
        assertEquals(null, identities.get(USER_ID))
    }

    @Test
    fun aRejectedDeletionCodeKeepsThePhoneSignedIn() = runTest {
        val engine = engine(backgroundScope)
        pairedAndConnected(engine)
        val failure = runCatching { engine.deleteAccount(111111) }.exceptionOrNull()

        assertTrue(failure is ApiException)
        assertTrue(!backend.accountDeleted)
        assertTrue(engine.state.value is SyncState.Ready)
        assertTrue(SessionStore(storage).get() != null)
    }

    @Test
    fun anAccountWithoutANameIsAskedOnceAndTheNameIsSaved() = runTest {
        SessionStore(storage).clear()
        val engine = SyncEngine(
            backend, "https://socket.example", { _, _, l -> listener = l; FakeSocket().also { socket = it } },
            SessionStore(storage), identities, TrustStore(storage), ProcessedItems(storage), platform, backgroundScope,
        )
        backend.addRoot()
        engine.signInWithGoogle("google-id-token")
        assertTrue(engine.needsName.value)

        engine.updateName("  Ada Obi ")

        assertEquals(listOf("Ada Obi"), backend.profileNames)
        assertEquals("Ada Obi", SessionStore(storage).get()!!.name)
        assertTrue(!engine.needsName.value)
    }

    @Test
    fun aStoredNameMeansNoNameStep() = runTest {
        SessionStore(storage).set(Session(jwt(), "refresh-1", USER_ID, "me@example.com", name = "Ada"))
        val engine = SyncEngine(
            backend, "https://socket.example", { _, _, l -> listener = l; FakeSocket().also { socket = it } },
            SessionStore(storage), identities, TrustStore(storage), ProcessedItems(storage), platform, backgroundScope,
        )
        assertTrue(!engine.needsName.value)
        val failure = runCatching { engine.updateName("   ") }.exceptionOrNull()
        assertTrue(failure is SyncException)
        assertTrue(backend.profileNames.isEmpty())
    }

    @Test
    fun signingIntoAnotherAccountKeepsThisAccountPaired() = runTest {
        val engine = engine(backgroundScope)
        pairedAndConnected(engine)
        val pairedId = androidId()

        engine.signOut()
        engine.signInWithGoogle(OTHER_ACCOUNT_TOKEN)
        assertEquals(SyncState.NoRoot(canBeFirstDevice = true), engine.state.value)
        engine.signOut()
        engine.signInWithGoogle("google-id-token")

        assertTrue(engine.state.value is SyncState.Ready)
        assertEquals(pairedId, androidId())
        assertEquals(1, backend.registrations.map { it.deviceId }.distinct().size)
    }

    @Test
    fun theSignedInAccountIsShownAndClearedOnSignOut() = runTest {
        val engine = engine(backgroundScope)
        assertEquals("me@example.com", engine.account.value?.email)

        engine.signOut()
        assertEquals(null, engine.account.value)
        engine.signInWithGoogle(OTHER_ACCOUNT_TOKEN)
        assertEquals("other@example.com", engine.account.value?.email)
        engine.updateName("Ada")
        assertEquals(AccountInfo("other@example.com", "Ada"), engine.account.value)
    }

    @Test
    fun pausedReceivingIgnoresIncomingItemsAndDropsTheConnection() = runTest {
        val engine = engine(backgroundScope)
        pairedAndConnected(engine)
        val standing = socket!!

        engine.setReceiveEnabled(false)
        assertTrue(standing.closed)
        assertTrue(!(engine.state.value as SyncState.Ready).connected)
        engine.receive(itemFromChrome("while paused"))
        assertTrue(platform.clipboard.isEmpty())

        engine.setReceiveEnabled(true)
        engine.refresh()
        listener!!.onReady()
        engine.receive(itemFromChrome("after resuming"))
        assertEquals(listOf("after resuming"), platform.clipboard)
    }

    @Test
    fun sendingWhilePausedConnectsOnlyForTheSend() = runTest {
        val engine = engine(backgroundScope)
        pairedAndConnected(engine)
        engine.setReceiveEnabled(false)

        val sending = async { engine.sendText("from a paused phone") }
        runCurrent()
        val temporary = socket!!
        assertTrue(!temporary.closed)
        listener!!.onReady()

        assertEquals(1, sending.await())
        assertEquals(1, temporary.published.size)
        assertTrue(temporary.closed)
        assertTrue(!(engine.state.value as SyncState.Ready).connected)
    }

    @Test
    fun thePausedChoiceIsRememberedOnThisPhone() = runTest {
        val preferences = PreferencesStore(storage)
        val first = SyncEngine(
            backend, "https://socket.example", { _, _, l -> listener = l; FakeSocket().also { socket = it } },
            SessionStore(storage), identities, TrustStore(storage), ProcessedItems(storage), platform, backgroundScope,
            preferences,
        )
        first.setReceiveEnabled(false)
        val second = SyncEngine(
            backend, "https://socket.example", { _, _, l -> listener = l; FakeSocket().also { socket = it } },
            SessionStore(storage), identities, TrustStore(storage), ProcessedItems(storage), platform, backgroundScope,
            preferences,
        )
        assertTrue(!second.receiveEnabled.value)
    }

    @Test
    fun googleSignInStoresTheSessionAndStarts() = runTest {
        SessionStore(storage).clear()
        val engine = SyncEngine(
            backend, "https://socket.example", { _, _, l -> listener = l; FakeSocket().also { socket = it } },
            SessionStore(storage), identities, TrustStore(storage), ProcessedItems(storage), platform, backgroundScope,
        )
        backend.addRoot()
        engine.signInWithGoogle("google-id-token")
        assertEquals("refresh-google", SessionStore(storage).get()!!.refreshToken)
        assertTrue(engine.state.value is SyncState.Pairing)
    }

    private suspend fun assertThrowsSync(block: suspend () -> Unit) {
        try {
            block()
        } catch (_: Exception) {
            return
        }
        throw AssertionError("Expected an exception")
    }
}

private val RecoveryStatusExported = com.copyyt.android.sync.RecoveryStatus(exportable = false, exported = true)
