package com.copyyt.android.net

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.IOException
import java.util.concurrent.TimeUnit

@Serializable
data class UserDto(
    val id: String,
    val email: String,
    val name: String? = null,
)

@Serializable
data class ProfileResponse(val user: UserDto)

@Serializable
data class SignInResponse(
    val accessToken: String,
    val refreshToken: String? = null,
    val user: UserDto,
)

@Serializable
data class DeviceDto(
    val deviceId: String,
    val name: String,
    val platform: String,
    val encryptionPublicKey: String,
    val signingPublicKey: String,
    val trustState: String,
    val keyVersion: Int,
    val capabilities: List<String> = emptyList(),
    val appVersion: String? = null,
    val approvedByDeviceId: String? = null,
    val approvalSignature: String? = null,
    val revokedAt: String? = null,
    val lastSeenAt: String? = null,
    /** Registration only: this device's recovery key is the account's active one. */
    val recoveryKeyActive: Boolean? = null,
    /** Recovery only: false when the server kept the old recovery key. */
    val recoveryKeyRotated: Boolean? = null,
)

@Serializable
data class RegisterDeviceRequest(
    val deviceId: String,
    val name: String,
    val platform: String,
    val encryptionPublicKey: String,
    val signingPublicKey: String,
    val capabilities: List<String>,
    val appVersion: String,
    val recoveryPublicKey: String? = null,
    val requestingDeviceId: String? = null,
    val requestingKeyVersion: Int? = null,
    val managementTimestamp: Long? = null,
    val managementNonce: String? = null,
    val managementSignature: String? = null,
)

@Serializable
data class RecipientDto(
    val deviceId: String,
    val deviceKeyVersion: Int,
    val wrapNonce: String,
    val wrappedContentKey: String,
)

@Serializable
data class ClipboardItemDto(
    val itemId: String,
    val sourceDeviceId: String,
    val sourceKeyVersion: Int,
    val sourceSignature: String,
    val protocolVersion: Int,
    val contentType: String,
    val ciphertext: String,
    val nonce: String,
    val recipients: List<RecipientDto>,
    val expiresAt: String,
)

@Serializable
data class ApproveDeviceRequest(
    val approvingDeviceId: String,
    val pendingDeviceId: String,
    val approvalSignature: String,
)

@Serializable
data class DeviceManagementRequest(
    val requestingDeviceId: String,
    val requestingKeyVersion: Int,
    val timestamp: Long,
    val nonce: String,
    val signature: String,
)

/** Exactly the backend RecoverDeviceDto fields (it rejects any others). */
@Serializable
data class RecoverDeviceRequest(
    val rootDeviceId: String,
    val deviceId: String,
    val name: String,
    val platform: String,
    val encryptionPublicKey: String,
    val signingPublicKey: String,
    val newRecoveryPublicKey: String,
    val capabilities: List<String>,
    val appVersion: String,
    val timestamp: Long,
    val nonce: String,
    val signature: String,
)

/** A non-2xx response. `code` is the backend's machine-readable error code. */
class ApiException(val status: Int, val code: String?, message: String) : IOException(message)

val CopyytJson = Json {
    ignoreUnknownKeys = true
    explicitNulls = false
}

/** The backend surface the sync engine uses; faked in unit tests. */
interface BackendApi {
    fun signInPasswordless(email: String)
    fun verifyEmail(email: String, code: Int, name: String?): SignInResponse
    fun refreshTokens(refreshToken: String): SignInResponse
    fun logout(refreshToken: String)
    fun registerDevice(token: String, request: RegisterDeviceRequest): DeviceDto
    fun listTrusted(token: String): List<DeviceDto>
    fun listPending(token: String): List<DeviceDto>
    fun latestItem(token: String, deviceId: String): ClipboardItemDto?
    fun googleSignIn(idToken: String): SignInResponse
    fun approveDevice(token: String, request: ApproveDeviceRequest): DeviceDto
    fun revokeDevice(token: String, deviceId: String, request: DeviceManagementRequest): DeviceDto
    fun recoverDevice(token: String, request: RecoverDeviceRequest): DeviceDto
    fun requestAccountResetCode(token: String)
    fun resetAccount(token: String, code: Int)
    fun requestAccountDeletionCode(token: String)
    fun deleteAccount(token: String, code: Int)
    fun updateProfile(token: String, name: String): UserDto
}

/** Thin REST client. Every request identifies as the native Android client. */
class CopyytApi(
    private val baseUrl: String,
    private val client: OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(20, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .build(),
) : BackendApi {
    private val jsonType = "application/json".toMediaType()

    private fun <T> call(
        method: String,
        path: String,
        body: String?,
        accessToken: String?,
        serializer: KSerializer<T>?,
    ): T? {
        val builder = Request.Builder()
            .url("$baseUrl/api/v1$path")
            .header("Accept", "application/json")
            .header("X-Copyyt-Client", "android")
        if (accessToken != null) builder.header("Authorization", "Bearer $accessToken")
        builder.method(method, body?.toRequestBody(jsonType))
        client.newCall(builder.build()).execute().use { response ->
            val text = response.body?.string().orEmpty()
            if (!response.isSuccessful) throw errorFrom(response.code, text)
            if (serializer == null || text.isBlank() || text == "null") return null
            return CopyytJson.decodeFromString(serializer, text)
        }
    }

    private fun errorFrom(status: Int, text: String): ApiException {
        val obj = runCatching { CopyytJson.parseToJsonElement(text) as JsonObject }.getOrNull()
        val code = obj?.get("code")?.jsonPrimitive?.contentOrNull
        val description = obj?.get("description")?.jsonPrimitive?.contentOrNull
            ?: obj?.get("message")?.jsonPrimitive?.contentOrNull
        // Nest validation failures report `message` as a list of problems.
        val problems = (obj?.get("message") as? kotlinx.serialization.json.JsonArray)
            ?.mapNotNull { (it as? kotlinx.serialization.json.JsonPrimitive)?.contentOrNull }
            ?.joinToString("; ")
        return ApiException(status, code, description ?: problems ?: "Request failed ($status)")
    }

    private fun json(vararg pairs: Pair<String, Any?>): String =
        CopyytJson.encodeToString(
            JsonObject.serializer(),
            JsonObject(
                pairs.filter { it.second != null }.associate { (key, value) ->
                    key to when (value) {
                        is Number -> kotlinx.serialization.json.JsonPrimitive(value)
                        else -> kotlinx.serialization.json.JsonPrimitive(value.toString())
                    }
                },
            ),
        )

    override fun signInPasswordless(email: String) {
        call<Unit>("POST", "/auth/sign-in-passwordless", json("email" to email), null, null)
    }

    override fun verifyEmail(email: String, code: Int, name: String?): SignInResponse =
        call(
            "POST", "/auth/verify-email",
            json("email" to email, "code" to code, "name" to name?.takeIf { it.isNotBlank() }),
            null, SignInResponse.serializer(),
        )!!

    override fun refreshTokens(refreshToken: String): SignInResponse =
        call(
            "POST", "/auth/refresh-tokens", json("refreshToken" to refreshToken),
            null, SignInResponse.serializer(),
        )!!

    override fun logout(refreshToken: String) {
        call<Unit>("POST", "/auth/logout", json("refreshToken" to refreshToken), null, null)
    }

    override fun registerDevice(token: String, request: RegisterDeviceRequest): DeviceDto =
        call(
            "POST", "/devices",
            CopyytJson.encodeToString(RegisterDeviceRequest.serializer(), request),
            token, DeviceDto.serializer(),
        )!!

    override fun listTrusted(token: String): List<DeviceDto> =
        call("GET", "/devices", null, token, ListSerializer(DeviceDto.serializer())).orEmpty()

    override fun listPending(token: String): List<DeviceDto> =
        call("GET", "/devices/pending", null, token, ListSerializer(DeviceDto.serializer())).orEmpty()

    override fun latestItem(token: String, deviceId: String): ClipboardItemDto? =
        call("GET", "/clipboard/items/latest?deviceId=$deviceId", null, token, ClipboardItemDto.serializer())

    override fun googleSignIn(idToken: String): SignInResponse =
        call("POST", "/auth/google-auth", json("idToken" to idToken), null, SignInResponse.serializer())!!

    override fun approveDevice(token: String, request: ApproveDeviceRequest): DeviceDto =
        call(
            "POST", "/devices/approve",
            CopyytJson.encodeToString(ApproveDeviceRequest.serializer(), request),
            token, DeviceDto.serializer(),
        )!!

    override fun revokeDevice(token: String, deviceId: String, request: DeviceManagementRequest): DeviceDto =
        call(
            "DELETE", "/devices/$deviceId",
            CopyytJson.encodeToString(DeviceManagementRequest.serializer(), request),
            token, DeviceDto.serializer(),
        )!!

    override fun recoverDevice(token: String, request: RecoverDeviceRequest): DeviceDto =
        call(
            "POST", "/devices/recover",
            CopyytJson.encodeToString(RecoverDeviceRequest.serializer(), request),
            token, DeviceDto.serializer(),
        )!!

    override fun requestAccountResetCode(token: String) {
        call<Unit>("POST", "/auth/account-reset/code", "{}", token, null)
    }

    override fun resetAccount(token: String, code: Int) {
        call<Unit>("POST", "/auth/account-reset", json("code" to code), token, null)
    }

    override fun requestAccountDeletionCode(token: String) {
        call<Unit>("POST", "/auth/account-delete/code", "{}", token, null)
    }

    override fun deleteAccount(token: String, code: Int) {
        call<Unit>("POST", "/auth/account-delete", json("code" to code), token, null)
    }

    override fun updateProfile(token: String, name: String): UserDto =
        call("PATCH", "/auth/profile", json("name" to name), token, ProfileResponse.serializer())!!.user
}
