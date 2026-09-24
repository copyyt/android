package com.copyyt.android.sync

import com.copyyt.android.protocol.B64
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.put

/**
 * Clipboard content the engine sends or receives: plain text, formatted
 * (HTML) text and/or a PNG image. HTML always travels with a plain-text
 * fallback.
 */
class ClipContent(
    val text: String? = null,
    val html: String? = null,
    val png: ByteArray? = null,
) {
    val isEmpty: Boolean get() = text.isNullOrEmpty() && png == null

    fun withoutImage(): ClipContent = ClipContent(text, html, null)
}

class ClipboardBundleException(message: String) : Exception(message)

/**
 * The extension's bundle-v1 wire format (`clipboard/payload.ts`): UTF-8 JSON
 * `{"version":1,"representations":[{"mime","encoding","data"}]}` with one to
 * three unique representations. Decoding is as strict as the extension's.
 */
object ClipboardBundle {
    const val MIME = "application/vnd.copyyt.clipboard-bundle+json"

    /** The relay's ciphertext limit minus the AES-GCM tag. */
    const val MAX_BYTES = 1024 * 1024 - 16

    /** Local ceiling for a decoded PNG, matching the extension. */
    const val MAX_LOCAL_PNG_BYTES = 8 * 1024 * 1024

    private val PNG_SIGNATURE = byteArrayOf(0x89.toByte(), 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a)

    fun hasPngSignature(bytes: ByteArray): Boolean =
        bytes.size >= PNG_SIGNATURE.size && PNG_SIGNATURE.indices.all { bytes[it] == PNG_SIGNATURE[it] }

    fun encode(content: ClipContent): ByteArray {
        val representations = buildJsonArray {
            content.text?.let { add(representation("text/plain", "utf-8", it)) }
            content.html?.let {
                if (content.text == null) throw ClipboardBundleException("HTML needs a plain-text fallback")
                add(representation("text/html", "utf-8", it))
            }
            content.png?.let {
                if (!hasPngSignature(it)) throw ClipboardBundleException("Not a PNG image")
                add(representation("image/png", "base64", B64.encode(it)))
            }
        }
        if (representations.isEmpty()) throw ClipboardBundleException("Nothing to send")
        val json = buildJsonObject {
            put("version", 1)
            put("representations", representations)
        }
        return json.toString().toByteArray(Charsets.UTF_8)
    }

    /** Encoded size, for shrinking an image until it fits [MAX_BYTES]. */
    fun encodedSize(content: ClipContent): Int = encode(content).size

    fun fits(content: ClipContent): Boolean = encodedSize(content) <= MAX_BYTES

    fun decode(bytes: ByteArray): ClipContent {
        if (bytes.size > MAX_BYTES) throw ClipboardBundleException("Clipboard bundle is too large")
        val text = try {
            Charsets.UTF_8.newDecoder().decode(java.nio.ByteBuffer.wrap(bytes)).toString()
        } catch (_: java.nio.charset.CharacterCodingException) {
            throw ClipboardBundleException("Clipboard bundle is not valid UTF-8")
        }
        val root = runCatching { kotlinx.serialization.json.Json.parseToJsonElement(text) }.getOrNull() as? JsonObject
            ?: throw ClipboardBundleException("Malformed clipboard bundle")
        if (root.keys != setOf("version", "representations")) throw ClipboardBundleException("Malformed clipboard bundle")
        if ((root["version"] as? JsonPrimitive)?.contentOrNull != "1" || (root["version"] as JsonPrimitive).isString) {
            throw ClipboardBundleException("Unsupported clipboard bundle version")
        }
        val list = root["representations"] as? JsonArray ?: throw ClipboardBundleException("Malformed clipboard bundle")
        if (list.size !in 1..3) throw ClipboardBundleException("A clipboard bundle has one to three representations")
        var plain: String? = null
        var html: String? = null
        var png: ByteArray? = null
        val seen = mutableSetOf<String>()
        for (element in list) {
            val entry = element as? JsonObject ?: throw ClipboardBundleException("Malformed representation")
            if (entry.keys != setOf("mime", "encoding", "data")) throw ClipboardBundleException("Malformed representation")
            val mime = entry.string("mime")
            val encoding = entry.string("encoding")
            val data = entry.string("data")
            if (!seen.add(mime)) throw ClipboardBundleException("Duplicate representation")
            when (mime) {
                "text/plain", "text/html" -> {
                    if (encoding != "utf-8") throw ClipboardBundleException("Text must be UTF-8")
                    if (mime == "text/plain") plain = data else html = data
                }
                "image/png" -> {
                    if (encoding != "base64") throw ClipboardBundleException("PNG must be base64")
                    if (data.length > 4 * ((MAX_LOCAL_PNG_BYTES + 2) / 3)) throw ClipboardBundleException("PNG is too large")
                    val bytes = runCatching { B64.decode(data) }.getOrNull()
                        ?: throw ClipboardBundleException("PNG is not valid base64")
                    if (bytes.isEmpty() || !hasPngSignature(bytes)) throw ClipboardBundleException("Not a PNG image")
                    png = bytes
                }
                else -> throw ClipboardBundleException("Unsupported representation")
            }
        }
        if (html != null && plain == null) throw ClipboardBundleException("HTML needs a plain-text fallback")
        return ClipContent(plain, html, png)
    }

    private fun representation(mime: String, encoding: String, data: String) = buildJsonObject {
        put("mime", mime)
        put("encoding", encoding)
        put("data", data)
    }

    private fun JsonObject.string(key: String): String {
        val value = this[key] as? JsonPrimitive
        if (value == null || !value.isString) throw ClipboardBundleException("Malformed representation")
        return value.content
    }
}
