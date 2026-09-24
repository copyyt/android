package com.copyyt.android.sync

import com.copyyt.android.crypto.CopyytCrypto
import com.copyyt.android.crypto.CryptoProtocolException
import com.copyyt.android.crypto.Envelope
import com.copyyt.android.crypto.EnvelopeRecipient
import com.copyyt.android.net.ApiException
import com.copyyt.android.net.ClipboardItemDto
import com.copyyt.android.net.ApproveDeviceRequest
import com.copyyt.android.net.BackendApi
import com.copyyt.android.net.DeviceManagementRequest
import com.copyyt.android.net.RecoverDeviceRequest
import com.copyyt.android.net.CopyytJson
import com.copyyt.android.net.DeviceDto
import com.copyyt.android.net.RecipientDto
import com.copyyt.android.net.RegisterDeviceRequest
import com.copyyt.android.net.SignInResponse
import com.copyyt.android.protocol.B64
import com.copyyt.android.protocol.Protocol
import com.copyyt.android.protocol.RecoveryCredential
import com.copyyt.android.store.DeviceIdentity
import com.copyyt.android.store.IdentityStore
import com.copyyt.android.store.ProcessedItems
import com.copyyt.android.store.Session
import com.copyyt.android.store.SessionStore
import com.copyyt.android.trust.LocalDevice
import com.copyyt.android.trust.LocalTrust
import com.copyyt.android.trust.TrustStore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.time.Duration
import java.time.Instant
import java.util.UUID
import kotlin.coroutines.resume

/** What the device can see about a device on the account, for display. */
data class PeerInfo(
    val deviceId: String,
    val name: String,
    val platform: String,
    val trusted: Boolean,
    val isSelf: Boolean = false,
    val isRoot: Boolean = false,
    val pending: Boolean = false,
)

/** A device waiting for this phone (the root) to approve it. */
data class PendingApproval(val deviceId: String, val name: String, val platform: String, val fingerprint: String)

data class RecoveryStatus(val exportable: Boolean, val exported: Boolean)

/** Who is signed in, for display. */
data class AccountInfo(val email: String, val name: String?)

sealed interface SyncState {
    data object SignedOut : SyncState
    data object Starting : SyncState

    /**
     * No active account root. With [canBeFirstDevice] the account has no
     * devices, so this phone can become the first one; otherwise the root was
     * removed and the phone can recover with the offline credential or reset.
     */
    data class NoRoot(val canBeFirstDevice: Boolean) : SyncState
    data class Pairing(val fingerprint: String, val rootName: String) : SyncState
    data class WaitingForApproval(val fingerprint: String, val rootName: String) : SyncState
    data class Ready(
        val connected: Boolean,
        val peers: List<PeerInfo>,
        val lastEvent: String? = null,
        val isRoot: Boolean = false,
        /** The root was removed; this phone still syncs but nothing new can pair. */
        val rootMissing: Boolean = false,
        val pendingApprovals: List<PendingApproval> = emptyList(),
        /** Root only. */
        val recovery: RecoveryStatus? = null,
    ) : SyncState
    data object Revoked : SyncState
    data class Error(val message: String) : SyncState
}

/** Platform side effects the engine needs, so it stays testable off-device. */
interface SyncPlatform {
    val deviceName: String
    val appVersion: String
    fun now(): Instant
    fun writeClipboard(content: ClipContent)
    fun notifyReceived(sourceName: String, content: ClipContent)
}

/** One live, authenticated Socket.IO session. */
interface SocketConnection {
    fun close()
    fun emitDeviceAuth(payload: JsonObject)
    fun publish(payload: JsonObject, onAck: (JsonObject?) -> Unit)
}

interface SocketListener {
    fun onChallenge(socketId: String, challenge: String)
    fun onReady()
    fun onItem(json: String)
    fun onClosed(authFailed: Boolean)
}

typealias SocketFactory = (url: String, accessToken: String, listener: SocketListener) -> SocketConnection

class SyncException(message: String) : Exception(message)

/**
 * The Android Copyyt client. Joins the account as a paired (non-root)
 * device, verifies peers locally, receives encrypted text over the relay and
 * writes it to the clipboard, and sends text on explicit user action.
 */
class SyncEngine(
    private val api: BackendApi,
    private val socketUrl: String,
    private val socketFactory: SocketFactory,
    private val sessions: SessionStore,
    private val identities: IdentityStore,
    private val trust: TrustStore,
    private val processed: ProcessedItems,
    private val platform: SyncPlatform,
    private val scope: CoroutineScope,
) {
    private val _state = MutableStateFlow<SyncState>(
        if (sessions.get() == null) SyncState.SignedOut else SyncState.Starting,
    )
    val state: StateFlow<SyncState> = _state.asStateFlow()

    /**
     * Email sign-in doesn't ask for a name up front (the server won't reveal
     * whether an account is new), so a signed-in account without one is asked
     * once, after sign-in.
     */
    private val _needsName = MutableStateFlow(sessions.get()?.let { it.name.isNullOrBlank() } ?: false)
    val needsName: StateFlow<Boolean> = _needsName.asStateFlow()

    private val _account = MutableStateFlow(sessions.get()?.let { AccountInfo(it.email, it.name) })
    val account: StateFlow<AccountInfo?> = _account.asStateFlow()

    init {
        sessions.get()?.let { trust.useAccount(it.userId) }
    }

    private val refreshLock = Mutex()
    private val tokenLock = Mutex()
    // Touched from Socket.IO callback threads as well as coroutines.
    @Volatile private var socket: SocketConnection? = null
    @Volatile private var socketReady = false
    private var reconnectJob: Job? = null
    private var pollJob: Job? = null
    private var reconnectDelayMs = INITIAL_RECONNECT_MS
    @Volatile private var serverTrustedIds: Set<String> = emptySet()
    @Volatile private var lastPending: List<DeviceDto> = emptyList()
    @Volatile private var recoveryKeyActive = false
    @Volatile private var rootMissing = false

    // ---- Sign-in -------------------------------------------------------

    fun requestCode(email: String) = api.signInPasswordless(email.trim())

    /** Native Google sign-in with the ID token from Credential Manager. */
    suspend fun signInWithGoogle(idToken: String) {
        saveSession(api.googleSignIn(idToken))
        refresh()
    }

    suspend fun verifyCode(email: String, code: Int) {
        val response = api.verifyEmail(email.trim(), code, null)
        saveSession(response)
        refresh()
    }

    /** Saves the account's display name and keeps the stored session in step. */
    suspend fun updateName(name: String) {
        val trimmed = name.trim()
        if (trimmed.isEmpty() || trimmed.length > 100) throw SyncException("Enter a name up to 100 characters")
        val user = authed { api.updateProfile(it, trimmed) }
        val session = sessions.get() ?: return
        if (session.userId != user.id) return
        sessions.set(session.copy(name = user.name ?: trimmed))
        _account.value = AccountInfo(session.email, user.name ?: trimmed)
        _needsName.value = false
    }

    private fun saveSession(response: SignInResponse) {
        val refreshToken = response.refreshToken
            ?: throw SyncException("The server did not return a refresh credential")
        sessions.set(
            Session(response.accessToken, refreshToken, response.user.id, response.user.email, response.user.name),
        )
        trust.useAccount(response.user.id)
        _account.value = AccountInfo(response.user.email, response.user.name)
        _needsName.value = response.user.name.isNullOrBlank()
    }

    fun signOut() {
        val session = sessions.get()
        val wasRevoked = _state.value == SyncState.Revoked
        closeSocket()
        pollJob?.cancel()
        // A revoked identity can never sync again; signing back in must start
        // over with a new identity rather than hit the same dead end. Other
        // accounts on this phone keep their identities and trust.
        if (wasRevoked) discardDeviceState()
        sessions.clear()
        _needsName.value = false
        _account.value = null
        _state.value = SyncState.SignedOut
        if (session != null) {
            scope.launch { runCatching { api.logout(session.refreshToken) } }
        }
    }

    /** Forgets this phone's identity and trust for the signed-in account only. */
    private fun discardDeviceState() {
        val userId = sessions.get()?.userId ?: return
        trust.useAccount(userId)
        identities.clear(userId)
        trust.clear()
        processed.clear()
    }

    /**
     * Sets a revoked device up again under a brand-new identity. It registers
     * as pending and must be paired and approved by the root like any new device.
     */
    suspend fun setUpAgain() {
        if (_state.value != SyncState.Revoked) throw SyncException("Only a removed device can be set up again")
        closeSocket()
        refreshLock.withLock { discardDeviceState() }
        refresh()
    }

    // ---- Tokens --------------------------------------------------------

    private suspend fun freshToken(): String = tokenLock.withLock {
        val session = sessions.get() ?: throw SyncException("Signed out")
        if (!tokenExpiresSoon(session.accessToken)) return session.accessToken
        refreshTokenLocked(session)
    }

    private fun refreshTokenLocked(session: Session): String {
        val response = try {
            api.refreshTokens(session.refreshToken)
        } catch (error: ApiException) {
            if (error.status == 400 || error.status == 401) {
                sessions.clear()
                closeSocket()
                _account.value = null
                _state.value = SyncState.SignedOut
            }
            throw error
        }
        saveSession(response)
        return response.accessToken
    }

    /** Runs an authenticated call, refreshing the access token once on 401. */
    private suspend fun <T> authed(block: (String) -> T): T {
        val token = freshToken()
        return try {
            block(token)
        } catch (error: ApiException) {
            if (error.status != 401) throw error
            val refreshed = tokenLock.withLock {
                refreshTokenLocked(sessions.get() ?: throw SyncException("Signed out"))
            }
            block(refreshed)
        }
    }

    private fun tokenExpiresSoon(jwt: String): Boolean = runCatching {
        val payload = jwt.split(".")[1]
        val json = String(java.util.Base64.getUrlDecoder().decode(payload))
        val exp = Json.parseToJsonElement(json).jsonObject["exp"]!!.jsonPrimitive.content.toLong()
        Instant.ofEpochSecond(exp).isBefore(platform.now().plusSeconds(60))
    }.getOrDefault(true)

    // ---- Registration, trust and pairing -------------------------------

    fun start() {
        if (sessions.get() == null) {
            _state.value = SyncState.SignedOut
            return
        }
        scope.launch { runCatching { refresh() } }
    }

    /** Re-reads server device state and derives this device's pairing/trust state. */
    suspend fun refresh() = refreshLock.withLock {
        val session = sessions.get() ?: run {
            _state.value = SyncState.SignedOut
            return@withLock
        }
        try {
            refreshLocked(session)
        } catch (error: ApiException) {
            if (sessions.get() != null) _state.value = SyncState.Error(error.message ?: "Server error")
        } catch (error: Exception) {
            _state.value = SyncState.Error(error.message ?: "Copyyt could not start")
        }
    }

    private suspend fun refreshLocked(session: Session) {
        trust.useAccount(session.userId)
        if (identities.get(session.userId) == null) trust.clear()
        var identity = identities.getOrCreate(session.userId)
        var trusted = authed { api.listTrusted(it) }

        if (identity.keyVersion == null && trusted.none { it.trustState == "trusted" }) {
            // Registering now would make this phone the account root. That is
            // allowed, but only as an explicit choice (setUpAsFirstDevice).
            _state.value = SyncState.NoRoot(canBeFirstDevice = true)
            return
        }
        identity = register(session, identity) ?: return
        trusted = authed { api.listTrusted(it) }
        val pending = authed { api.listPending(it) }
        serverTrustedIds = trusted.map { it.deviceId }.toSet()
        lastPending = pending
        for (device in trusted + pending) trust.upsertServerReported(session.userId, device)

        val root = resolveAccountRoot(trusted)
        val mePending = pending.find { it.deviceId == identity.deviceId }
        val meTrusted = trusted.find { it.deviceId == identity.deviceId }

        if (meTrusted != null) {
            reconcileApprovals(session.userId, trusted)
            if (trust.get(identity.deviceId)?.locallyVerified == true) {
                pollJob?.cancel()
                rootMissing = root == null
                publishReady()
                connectSocket()
                return
            }
        }
        val me = mePending ?: meTrusted ?: throw SyncException("This device is not registered")
        if (root == null) {
            // No active root to pair with: recover with the offline credential or reset.
            _state.value = SyncState.NoRoot(canBeFirstDevice = false)
            return
        }
        if (root.deviceId == identity.deviceId) {
            // The server made this phone the root but setup did not finish.
            _state.value = SyncState.NoRoot(canBeFirstDevice = true)
            return
        }
        val pinned = trust.get(root.deviceId)?.takeIf {
            it.trust == LocalTrust.ROOT && it.pairedForDeviceId == identity.deviceId
        }
        if (pinned != null) {
            if (meTrusted != null) {
                throw SyncException("This device was approved, but its approval could not be verified locally")
            }
            _state.value = SyncState.WaitingForApproval(pinned.pairingFingerprint.orEmpty(), root.name)
            startApprovalPolling()
            return
        }
        _state.value = SyncState.Pairing(pairingFingerprint(identity.userId, root, me), root.name)
    }

    private fun baseRegistration(identity: DeviceIdentity) = RegisterDeviceRequest(
        deviceId = identity.deviceId,
        name = platform.deviceName.take(100),
        platform = PLATFORM,
        encryptionPublicKey = identity.keys.encryptionPublicKeyBase64,
        signingPublicKey = identity.keys.signingPublicKeyBase64,
        capabilities = CAPABILITIES,
        appVersion = platform.appVersion,
        // Only a root (or a phone becoming one) has a recovery key; others omit it.
        recoveryPublicKey = identity.recoveryPublicKey,
    )

    private suspend fun register(session: Session, identity: DeviceIdentity): DeviceIdentity? {
        val base = baseRegistration(identity)
        val keyVersion = identity.keyVersion
        val request = if (keyVersion == null) base else {
            val timestamp = platform.now().toEpochMilli()
            val nonce = UUID.randomUUID().toString()
            val message = Protocol.deviceManagementMessage(
                "update", session.userId, identity.deviceId, keyVersion, identity.deviceId, keyVersion,
                timestamp, nonce, base.name, base.platform, base.capabilities, base.appVersion,
                base.recoveryPublicKey,
            )
            base.copy(
                requestingDeviceId = identity.deviceId,
                requestingKeyVersion = keyVersion,
                managementTimestamp = timestamp,
                managementNonce = nonce,
                managementSignature = B64.encode(identity.keys.sign(message)),
            )
        }
        val device = try {
            authed { api.registerDevice(it, request) }
        } catch (error: ApiException) {
            if (error.code == "device_revoked") {
                closeSocket()
                _state.value = SyncState.Revoked
                return null
            }
            throw error
        }
        if (device.deviceId != identity.deviceId ||
            device.encryptionPublicKey != identity.keys.encryptionPublicKeyBase64 ||
            device.signingPublicKey != identity.keys.signingPublicKeyBase64
        ) {
            throw SyncException("The registration response does not match this device")
        }
        recoveryKeyActive = device.recoveryKeyActive == true
        return if (device.keyVersion == identity.keyVersion) identity
        else identities.setKeyVersion(identity, device.keyVersion)
    }

    /** Bounded fixed-point walk: each pass can add one verified vertex. */
    private fun reconcileApprovals(userId: String, trusted: List<DeviceDto>) {
        repeat(maxOf(1, trusted.size)) {
            var promoted = false
            for (device in trusted) {
                if (trust.applyApproval(userId, device)) promoted = true
            }
            if (!promoted) return
        }
    }

    private fun pairingFingerprint(userId: String, approver: DeviceDto, pending: DeviceDto): String =
        Protocol.pairingFingerprint(
            Protocol.pairingFingerprintContext(
                userId, approver.deviceId, approver.keyVersion, approver.signingPublicKey,
                approver.encryptionPublicKey, pending.deviceId, pending.keyVersion, pending.signingPublicKey,
                pending.encryptionPublicKey,
            ),
        )

    /** Called after the user confirmed the fingerprint matches the one on the root device. */
    suspend fun confirmPairing() {
        refreshLock.withLock {
            val session = sessions.get() ?: return@withLock
            val identity = identities.get(session.userId) ?: return@withLock
            val trusted = authed { api.listTrusted(it) }
            val root = resolveAccountRoot(trusted) ?: throw SyncException("The account root is unavailable")
            val pending = authed { api.listPending(it) }
            val me = (pending + trusted).find { it.deviceId == identity.deviceId }
                ?: throw SyncException("This device is not registered")
            trust.upsertServerReported(session.userId, root)
            trust.pinPairedRoot(root.deviceId, identity.deviceId, pairingFingerprint(identity.userId, root, me))
        }
        refresh()
    }

    private fun startApprovalPolling() {
        if (pollJob?.isActive == true) return
        pollJob = scope.launch {
            while (true) {
                delay(APPROVAL_POLL_MS)
                if (_state.value !is SyncState.WaitingForApproval) break
                refresh()
            }
        }
    }

    // ---- Becoming and being the account root ---------------------------

    /**
     * Makes this phone the account's first device (trust on first use). The
     * server only grants that when the account has no root anchor; otherwise
     * the phone ends up pending and must recover or be approved.
     */
    suspend fun setUpAsFirstDevice() {
        refreshLock.withLock {
            val session = sessions.get() ?: throw SyncException("Sign in first")
            var identity = identities.ensureRecoveryKey(identities.getOrCreate(session.userId))
            identity = register(session, identity) ?: return@withLock
            val trusted = authed { api.listTrusted(it) }
            val root = resolveAccountRoot(trusted)
            val me = trusted.find { it.deviceId == identity.deviceId }
            if (me == null || root?.deviceId != identity.deviceId || trusted.size != 1) {
                throw SyncException(
                    "This account already has a root device. Pair with it, recover, or reset the account.",
                )
            }
            trust.clear()
            trust.upsertServerReported(session.userId, me)
            trust.pinSelfAsRoot(trust.get(me.deviceId)!!, LocalDevice.ORIGIN_FIRST_DEVICE)
        }
        refresh()
    }

    private fun currentIdentity(): Pair<Session, DeviceIdentity> {
        val session = sessions.get() ?: throw SyncException("Sign in first")
        val identity = identities.get(session.userId) ?: throw SyncException("This device is not set up")
        return session to identity
    }

    private fun requireApprovingRoot(identity: DeviceIdentity): Int {
        val keyVersion = identity.keyVersion ?: throw SyncException("This device is not registered")
        if (trust.get(identity.deviceId)?.approvingRoot != true) {
            throw SyncException("Only the account root can do this")
        }
        return keyVersion
    }

    /**
     * Approves a pending device after the user typed the fingerprint shown on
     * it. The typed code must match what this phone computes from both keys.
     */
    suspend fun approveDevice(pendingDeviceId: String, typedFingerprint: String) {
        refreshLock.withLock {
            val (session, identity) = currentIdentity()
            val keyVersion = requireApprovingRoot(identity)
            val trusted = authed { api.listTrusted(it) }
            val self = trusted.find { it.deviceId == identity.deviceId }
                ?: throw SyncException("This device is no longer trusted")
            val pending = authed { api.listPending(it) }.find { it.deviceId == pendingDeviceId }
                ?: throw SyncException("That device is no longer waiting for approval")
            val expected = pairingFingerprint(session.userId, self, pending)
            if (normalizeFingerprint(typedFingerprint) != normalizeFingerprint(expected)) {
                throw SyncException("The code doesn't match. Check it on the new device and try again.")
            }
            val signature = identity.keys.sign(
                Protocol.deviceApprovalMessage(
                    session.userId, identity.deviceId, keyVersion, pending.deviceId, pending.keyVersion,
                    pending.encryptionPublicKey, pending.signingPublicKey,
                ),
            )
            val approved = authed {
                api.approveDevice(
                    it,
                    ApproveDeviceRequest(identity.deviceId, pending.deviceId, B64.encode(signature)),
                )
            }
            trust.upsertServerReported(session.userId, pending)
            if (!trust.applyApproval(session.userId, approved)) {
                throw SyncException("The approval could not be verified locally")
            }
        }
        refresh()
    }

    /** Removes another device with a request signed by this (trusted) device. */
    suspend fun removeDevice(deviceId: String) {
        refreshLock.withLock {
            val (session, identity) = currentIdentity()
            val keyVersion = identity.keyVersion ?: throw SyncException("This device is not registered")
            if (deviceId == identity.deviceId) throw SyncException("Remove this device from another trusted device")
            if (trust.get(identity.deviceId)?.locallyVerified != true) {
                throw SyncException("Only a trusted device can remove other devices")
            }
            val target = (authed { api.listTrusted(it) } + authed { api.listPending(it) })
                .find { it.deviceId == deviceId } ?: throw SyncException("That device is not on this account")
            val timestamp = platform.now().toEpochMilli()
            val nonce = UUID.randomUUID().toString()
            val signature = identity.keys.sign(
                Protocol.deviceManagementMessage(
                    "revoke", session.userId, identity.deviceId, keyVersion, target.deviceId,
                    target.keyVersion, timestamp, nonce, null, null, null, null, null,
                ),
            )
            authed {
                api.revokeDevice(
                    it, target.deviceId,
                    DeviceManagementRequest(identity.deviceId, keyVersion, timestamp, nonce, B64.encode(signature)),
                )
            }
            trust.revoke(target.deviceId)
        }
        refresh()
    }

    /**
     * The offline recovery credential, shown once. Only available on the root
     * after the server confirmed this phone's recovery key is the active one.
     */
    fun exportRecoveryCredential(): String {
        val (_, identity) = currentIdentity()
        requireApprovingRoot(identity)
        val seed = identity.recoverySeed
        if (!recoveryKeyActive || seed == null || identity.recoveryExportedAt != null) {
            throw SyncException("The recovery credential is not available to export")
        }
        return RecoveryCredential.format(identity.deviceId, seed)
    }

    /** Deletes the recovery private key once the user saved it offline. */
    fun confirmRecoverySaved() {
        val (_, identity) = currentIdentity()
        requireApprovingRoot(identity)
        identities.sealRecovery(identity, Protocol.canonicalExpiry(platform.now()))
        if (_state.value is SyncState.Ready) publishReady()
    }

    /**
     * Makes this phone the account root with the offline recovery credential,
     * after the previous root was removed. Works for a remaining trusted phone
     * (promoted in place) or a pending one. The credential is rotated.
     */
    suspend fun recoverAsRoot(credentialText: String) {
        val parsed = RecoveryCredential.parse(credentialText)
        refreshLock.withLock {
            val session = sessions.get() ?: throw SyncException("Sign in first")
            var identity = identities.getOrCreate(session.userId)
            if (identity.keyVersion == null) identity = register(session, identity) ?: return@withLock
            val base = baseRegistration(identity)
            val newSeed = com.google.crypto.tink.subtle.Ed25519Sign.KeyPair.newKeyPair().privateKey
            val newPublic = B64.encode(com.google.crypto.tink.subtle.Ed25519Sign.KeyPair.newKeyPairFromSeed(newSeed).publicKey)
            val timestamp = platform.now().toEpochMilli()
            val nonce = UUID.randomUUID().toString()
            val message = Protocol.deviceRecoveryMessage(
                session.userId, parsed.rootDeviceId, identity.deviceId, base.name, base.platform,
                base.encryptionPublicKey, base.signingPublicKey, base.capabilities, base.appVersion,
                timestamp, nonce, newPublic,
            )
            val signature = com.google.crypto.tink.subtle.Ed25519Sign(parsed.seed).sign(message)
            val device = authed {
                api.recoverDevice(
                    it,
                    RecoverDeviceRequest(
                        rootDeviceId = parsed.rootDeviceId,
                        deviceId = identity.deviceId,
                        name = base.name,
                        platform = base.platform,
                        encryptionPublicKey = base.encryptionPublicKey,
                        signingPublicKey = base.signingPublicKey,
                        newRecoveryPublicKey = newPublic,
                        capabilities = base.capabilities,
                        appVersion = base.appVersion,
                        timestamp = timestamp,
                        nonce = nonce,
                        signature = B64.encode(signature),
                    ),
                )
            }
            if (device.deviceId != identity.deviceId || device.trustState != "trusted" ||
                device.signingPublicKey != identity.keys.signingPublicKeyBase64
            ) {
                throw SyncException("The recovery response does not match this device")
            }
            if (device.keyVersion != identity.keyVersion) identity = identities.setKeyVersion(identity, device.keyVersion)
            // If the server kept the old key, keep ours unchanged; the next
            // signed registration retries the rotation (recoveryKeyActive).
            if (device.recoveryKeyRotated != false) identity = identities.setRecoveryKey(identity, newSeed)
            else identity = identities.ensureRecoveryKey(identity)
            trust.upsertServerReported(session.userId, device)
            trust.pinSelfAsRoot(trust.get(device.deviceId)!!, LocalDevice.ORIGIN_RECOVERY)
        }
        refresh()
    }

    fun requestAccountResetCode() {
        val session = sessions.get() ?: throw SyncException("Sign in first")
        api.requestAccountResetCode(session.accessToken)
    }

    /**
     * Account reset, confirmed with an emailed code: the server removes every
     * device and the recovery anchor. This phone starts over and can then be
     * set up as the first device.
     */
    suspend fun resetAccount(code: Int) {
        if (code !in 100000..999999) throw SyncException("Enter the 6-digit code from the email")
        authed { api.resetAccount(it, code) }
        closeSocket()
        refreshLock.withLock { discardDeviceState() }
        refresh()
    }

    fun requestAccountDeletionCode() {
        val session = sessions.get() ?: throw SyncException("Sign in first")
        api.requestAccountDeletionCode(session.accessToken)
    }

    /**
     * Permanent account deletion, confirmed with an emailed code. The server
     * removes the account and all its data; this phone forgets its identity,
     * trust and session and returns to sign-in.
     */
    suspend fun deleteAccount(code: Int) {
        if (code !in 100000..999999) throw SyncException("Enter the 6-digit code from the email")
        authed { api.deleteAccount(it, code) }
        closeSocket()
        pollJob?.cancel()
        refreshLock.withLock { discardDeviceState() }
        sessions.clear()
        _needsName.value = false
        _account.value = null
        _state.value = SyncState.SignedOut
    }

    private fun publishReady(lastEvent: String? = null) {
        val previous = _state.value as? SyncState.Ready
        val session = sessions.get()
        val identity = session?.let { identities.get(it.userId) }
        val self = identity?.let { trust.get(it.deviceId) }
        val isRoot = self?.approvingRoot == true
        val approvals = if (isRoot && identity != null && self != null) {
            lastPending.filter { it.deviceId != identity.deviceId }.map { pending ->
                PendingApproval(
                    deviceId = pending.deviceId,
                    name = pending.name,
                    platform = pending.platform,
                    fingerprint = Protocol.pairingFingerprint(
                        Protocol.pairingFingerprintContext(
                            identity.userId, self.deviceId, self.keyVersion, self.signingPublicKey,
                            self.encryptionPublicKey, pending.deviceId, pending.keyVersion,
                            pending.signingPublicKey, pending.encryptionPublicKey,
                        ),
                    ),
                )
            }
        } else emptyList()
        _state.value = SyncState.Ready(
            connected = socketReady,
            peers = peers(identity?.deviceId),
            lastEvent = lastEvent ?: previous?.lastEvent,
            isRoot = isRoot,
            rootMissing = rootMissing,
            pendingApprovals = approvals,
            recovery = if (isRoot && identity != null) {
                RecoveryStatus(
                    exportable = recoveryKeyActive && identity.recoverySeed != null && identity.recoveryExportedAt == null,
                    exported = identity.recoveryExportedAt != null,
                )
            } else null,
        )
    }

    private fun peers(selfId: String?): List<PeerInfo> {
        val rootId = trust.all().firstOrNull { it.trust == LocalTrust.ROOT && it.deviceId in serverTrustedIds }?.deviceId
        val trustedPeers = trust.all()
            .filter { it.trust != LocalTrust.REVOKED && it.deviceId in serverTrustedIds }
            .map {
                PeerInfo(
                    deviceId = it.deviceId,
                    name = it.name ?: "Device",
                    platform = it.platform ?: "unknown",
                    trusted = it.locallyVerified,
                    isSelf = it.deviceId == selfId,
                    isRoot = it.deviceId == rootId && !rootMissing,
                )
            }
        val pendingPeers = lastPending
            .filter { it.deviceId !in serverTrustedIds }
            .map { PeerInfo(it.deviceId, it.name, it.platform, trusted = false, isSelf = it.deviceId == selfId, pending = true) }
        return (trustedPeers + pendingPeers).sortedWith(compareBy({ !it.isSelf }, { !it.isRoot }, { it.name }))
    }

    // ---- Socket session ------------------------------------------------

    private suspend fun connectSocket() {
        if (socket != null) return
        val token = freshToken()
        socketReady = false
        socket = socketFactory(socketUrl, token, Listener())
    }

    private fun closeSocket() {
        reconnectJob?.cancel()
        socket?.close()
        socket = null
        socketReady = false
    }

    private inner class Listener : SocketListener {
        override fun onChallenge(socketId: String, challenge: String) {
            val session = sessions.get() ?: return
            val identity = identities.get(session.userId) ?: return
            val keyVersion = identity.keyVersion ?: return
            val signature = identity.keys.sign(
                Protocol.socketAuthMessage(session.userId, identity.deviceId, keyVersion, socketId, challenge),
            )
            socket?.emitDeviceAuth(
                JsonObject(
                    mapOf(
                        "deviceId" to kotlinx.serialization.json.JsonPrimitive(identity.deviceId),
                        "keyVersion" to kotlinx.serialization.json.JsonPrimitive(keyVersion),
                        "signature" to kotlinx.serialization.json.JsonPrimitive(B64.encode(signature)),
                    ),
                ),
            )
        }

        override fun onReady() {
            socketReady = true
            reconnectDelayMs = INITIAL_RECONNECT_MS
            publishReady()
            scope.launch { fetchLatest() }
        }

        override fun onItem(json: String) {
            scope.launch {
                runCatching { CopyytJson.decodeFromString(ClipboardItemDto.serializer(), json) }
                    .onSuccess { receive(it) }
            }
        }

        override fun onClosed(authFailed: Boolean) {
            socket = null
            socketReady = false
            if (_state.value is SyncState.Ready) publishReady()
            scheduleReconnect(authFailed)
        }
    }

    private fun scheduleReconnect(authFailed: Boolean) {
        if (sessions.get() == null || reconnectJob?.isActive == true) return
        reconnectJob = scope.launch {
            delay(reconnectDelayMs)
            reconnectDelayMs = minOf(reconnectDelayMs * 2, MAX_RECONNECT_MS)
            // An auth failure can mean an expired token or a revoked device:
            // a full refresh re-registers and re-derives trust before reconnecting.
            if (authFailed) refresh() else runCatching { connectSocket() }.onFailure { scheduleReconnect(false) }
        }
    }

    private suspend fun fetchLatest() {
        val session = sessions.get() ?: return
        val identity = identities.get(session.userId) ?: return
        val item = runCatching { authed { api.latestItem(it, identity.deviceId) } }.getOrNull() ?: return
        receive(item)
    }

    // ---- Receive -------------------------------------------------------

    internal suspend fun receive(item: ClipboardItemDto) {
        val session = sessions.get() ?: return
        val identity = identities.get(session.userId) ?: return
        val keyVersion = identity.keyVersion ?: return
        if (processed.contains(item.itemId)) return
        val now = platform.now()
        val expiresAt = runCatching { Protocol.parseIso(item.expiresAt) }.getOrNull()
        if (expiresAt == null || !now.isBefore(expiresAt) ||
            expiresAt.isAfter(now.plus(LIVE_TTL).plus(MAX_CLOCK_SKEW))
        ) {
            processed.mark(item.itemId)
            return
        }
        var source = trust.get(item.sourceDeviceId)
        if (source?.locallyVerified != true) {
            // A newly approved device: refresh trust once before giving up.
            refresh()
            source = trust.get(item.sourceDeviceId)
            if (source?.locallyVerified != true) return
        }
        if (item.contentType != TEXT_PLAIN && item.contentType != ClipboardBundle.MIME) {
            processed.mark(item.itemId)
            return
        }
        val plaintext = try {
            CopyytCrypto.decrypt(session.userId, identity.deviceId, keyVersion, identity.keys, source.toPeer(), item.toEnvelope())
        } catch (_: CryptoProtocolException) {
            processed.mark(item.itemId)
            return
        }
        processed.mark(item.itemId)
        val content = if (item.contentType == TEXT_PLAIN) {
            ClipContent(text = plaintext.toString(Charsets.UTF_8))
        } else {
            try {
                ClipboardBundle.decode(plaintext)
            } catch (_: ClipboardBundleException) {
                return
            }
        }
        platform.writeClipboard(content)
        val sourceName = source.name ?: "another device"
        platform.notifyReceived(sourceName, content)
        if (_state.value is SyncState.Ready) publishReady("Received from $sourceName")
    }

    // ---- Send ----------------------------------------------------------

    /** Encrypts [text] for every locally verified, text-capable peer and publishes it. */
    suspend fun sendText(text: String): Int = sendClip(ClipContent(text = text))

    /**
     * Sends text, formatted text and/or an image. Each peer gets the richest
     * form it supports (plain text for text-only peers). Images are part of
     * Copyyt Pro; on Free, text sent with an image still goes. Returns the
     * number of devices it was sent to.
     */
    suspend fun sendClip(input: ClipContent): Int {
        if (input.isEmpty) throw SyncException("There is nothing to send")
        val session = sessions.get() ?: throw SyncException("Sign in to Copyyt first")
        if (!socketReady) {
            start()
            withTimeoutOrNull(SEND_CONNECT_TIMEOUT_MS) {
                _state.first { it is SyncState.Ready && it.connected }
            } ?: throw SyncException("Copyyt is not connected yet")
        }
        val identity = identities.get(session.userId) ?: throw SyncException("This device is not set up")
        val keyVersion = identity.keyVersion ?: throw SyncException("This device is not registered")
        // Re-read membership right before encrypting: a removed device must
        // not get a wrapped key (the server would reject the whole item) and
        // a newly approved one should be included.
        val trusted = authed { api.listTrusted(it) }
        serverTrustedIds = trusted.map { it.deviceId }.toSet()
        for (device in trusted) trust.upsertServerReported(session.userId, device)
        reconcileApprovals(session.userId, trusted)
        val peers = trust.all()
            .filter {
                it.locallyVerified && it.deviceId != identity.deviceId &&
                    it.deviceId in serverTrustedIds && CLIPBOARD_CAPABILITY in it.capabilities
            }
        if (peers.isEmpty()) throw SyncException("No paired device can receive it yet")

        var content = input
        if (content.png != null && runCatching { authed { api.getPlan(it) } }.getOrNull()?.limits?.images == false) {
            if (content.text.isNullOrEmpty()) throw SyncException("Copying images between devices is part of Copyyt Pro")
            content = content.withoutImage()
        }

        // One encrypted item per distinct form, like the extension's projections.
        val groups = linkedMapOf<Pair<String, List<String>>, Pair<ByteArray, MutableList<LocalDevice>>>()
        for (peer in peers) {
            val projected = projectFor(content, peer) ?: continue
            val (contentType, bytes) = wireForm(projected) ?: continue
            val key = contentType to listOfNotNull(projected.text, projected.html, projected.png?.let(B64::encode))
            groups.getOrPut(key) { bytes to mutableListOf() }.second += peer
        }
        if (groups.isEmpty()) throw SyncException("None of your paired devices can receive this yet")

        val expiry = Protocol.canonicalExpiry(platform.now().plus(LIVE_TTL))
        var delivered = 0
        for ((key, group) in groups) {
            val (bytes, recipients) = group
            val envelope = CopyytCrypto.encryptText(
                session.userId, identity.deviceId, keyVersion, identity.keys,
                bytes, key.first, expiry, recipients.map { it.toPeer() },
            )
            publish(envelope)
            delivered += recipients.size
        }
        publishReady("Sent to $delivered device(s)")
        return delivered
    }

    /** The richest form of [content] that [peer] advertises support for. */
    private fun projectFor(content: ClipContent, peer: LocalDevice): ClipContent? {
        val bundle = BUNDLE_CAPABILITY in peer.capabilities
        val html = content.html?.takeIf { bundle && HTML_CAPABILITY in peer.capabilities }
        val png = content.png?.takeIf { bundle && PNG_CAPABILITY in peer.capabilities }
        if (content.text == null && png == null) return null
        return ClipContent(content.text, html?.takeIf { content.text != null }, png)
    }

    /** Plain text travels as raw UTF-8; anything richer as a bundle. */
    private fun wireForm(content: ClipContent): Pair<String, ByteArray>? {
        if (content.html == null && content.png == null) {
            return TEXT_PLAIN to content.text!!.toByteArray(Charsets.UTF_8)
        }
        val bundle = ClipboardBundle.encode(content)
        if (bundle.size <= ClipboardBundle.MAX_BYTES) return ClipboardBundle.MIME to bundle
        // Too large for the relay: fall back to the text, if there is any.
        val text = content.text ?: return null
        return wireForm(ClipContent(text = text))
    }

    private suspend fun publish(envelope: Envelope) {
        val payload = CopyytJson.encodeToJsonElement(ClipboardItemDto.serializer(), envelope.toDto()).jsonObject
        val connection = socket ?: throw SyncException("Copyyt is not connected")
        val accepted = withTimeoutOrNull(PUBLISH_TIMEOUT_MS) {
            suspendCancellableCoroutine { continuation ->
                connection.publish(payload) { ack ->
                    val ok = ack?.get("accepted")?.jsonPrimitive?.content == "true" &&
                        ack["itemId"]?.jsonPrimitive?.content == envelope.itemId
                    if (continuation.isActive) continuation.resume(ok)
                }
            }
        }
        if (accepted != true) throw SyncException("The server did not accept the clipboard item")
        processed.mark(envelope.itemId)
    }

    companion object {
        const val CLIPBOARD_CAPABILITY = "clipboard"
        const val BUNDLE_CAPABILITY = "clipboard-bundle-v1"
        const val HTML_CAPABILITY = "clipboard-html-v1"
        /** The extension's name for "can receive PNG bundles". */
        const val PNG_CAPABILITY = "clipboard-image-png-assisted-write-v1"
        const val PLATFORM = "android"
        val CAPABILITIES = listOf(CLIPBOARD_CAPABILITY, BUNDLE_CAPABILITY, HTML_CAPABILITY, PNG_CAPABILITY)
        const val TEXT_PLAIN = "text/plain"
        val LIVE_TTL: Duration = Duration.ofSeconds(60)
        val MAX_CLOCK_SKEW: Duration = Duration.ofMinutes(5)
        const val INITIAL_RECONNECT_MS = 2_000L
        const val MAX_RECONNECT_MS = 60_000L
        const val APPROVAL_POLL_MS = 5_000L
        const val SEND_CONNECT_TIMEOUT_MS = 15_000L
        const val PUBLISH_TIMEOUT_MS = 10_000L

        /** Case- and separator-insensitive comparison of typed pairing codes. */
        fun normalizeFingerprint(value: String): String =
            value.uppercase().filter { it.isLetterOrDigit() }

        /** The account root is the single active trusted device without an approval certificate. */
        fun resolveAccountRoot(trusted: List<DeviceDto>): DeviceDto? =
            trusted.filter {
                it.trustState == "trusted" && it.revokedAt == null &&
                    it.approvedByDeviceId == null && it.approvalSignature == null
            }.singleOrNull()
    }
}

private fun ClipboardItemDto.toEnvelope() = Envelope(
    itemId, sourceDeviceId, sourceKeyVersion, sourceSignature, protocolVersion, contentType,
    ciphertext, nonce, recipients.map { EnvelopeRecipient(it.deviceId, it.deviceKeyVersion, it.wrapNonce, it.wrappedContentKey) },
    expiresAt,
)

private fun Envelope.toDto() = ClipboardItemDto(
    itemId, sourceDeviceId, sourceKeyVersion, sourceSignature, protocolVersion, contentType,
    ciphertext, nonce, recipients.map { RecipientDto(it.deviceId, it.deviceKeyVersion, it.wrapNonce, it.wrappedContentKey) },
    expiresAt,
)
