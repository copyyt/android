package com.copyyt.android.app

import android.content.ClipData
import android.content.ClipDescription
import android.content.ContentResolver
import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.net.Uri
import androidx.core.content.FileProvider
import androidx.core.graphics.scale
import com.copyyt.android.sync.ClipContent
import com.copyyt.android.sync.ClipboardBundle
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.UUID
import kotlin.math.max
import kotlin.math.sqrt

/** An outgoing clip, and whether its image had to be shrunk to fit the relay. */
class PreparedClip(val content: ClipContent, val resized: Boolean)

/** Reading, shrinking and exposing clipboard images. */
object ClipImages {
    /** Decoding cap, so a huge photo can't exhaust memory before shrinking. */
    private const val MAX_DECODE_EDGE = 4096
    private const val MIN_EDGE = 64
    private const val MAX_ATTEMPTS = 8
    private const val KEEP_RECEIVED = 3

    /**
     * Turns an image the user chose to send into a PNG that fits the relay,
     * along with any text sent with it. PNGs that already fit go unchanged;
     * anything else is re-encoded as PNG and scaled down until it fits.
     */
    fun prepare(resolver: ContentResolver, uri: Uri, text: String? = null, html: String? = null): PreparedClip {
        val original = resolver.openInputStream(uri)?.use { it.readBytes() }
            ?: throw IllegalStateException("The image could not be read")
        if (ClipboardBundle.hasPngSignature(original)) {
            val asIs = ClipContent(text, html, original)
            if (ClipboardBundle.fits(asIs)) return PreparedClip(asIs, resized = false)
        }
        var bitmap = decodeBounded(original) ?: throw IllegalStateException("That file isn't an image Copyyt can send")
        var resized = max(bitmap.width, bitmap.height) < originalEdge(original)
        repeat(MAX_ATTEMPTS) {
            val png = encodePng(bitmap)
            val candidate = ClipContent(text, html, png)
            val size = ClipboardBundle.encodedSize(candidate)
            if (size <= ClipboardBundle.MAX_BYTES) return PreparedClip(candidate, resized)
            val scale = sqrt(ClipboardBundle.MAX_BYTES.toDouble() / size) * 0.9
            val width = (bitmap.width * scale).toInt()
            val height = (bitmap.height * scale).toInt()
            if (width < MIN_EDGE || height < MIN_EDGE) throw IllegalStateException("The image is too large to send")
            bitmap = bitmap.scale(width, height)
            resized = true
        }
        throw IllegalStateException("The image is too large to send")
    }

    private fun originalEdge(bytes: ByteArray): Int {
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeByteArray(bytes, 0, bytes.size, bounds)
        return max(bounds.outWidth, bounds.outHeight)
    }

    private fun decodeBounded(bytes: ByteArray): Bitmap? {
        var sample = 1
        val edge = originalEdge(bytes)
        while (edge / sample > MAX_DECODE_EDGE) sample *= 2
        val options = BitmapFactory.Options().apply { inSampleSize = sample }
        return BitmapFactory.decodeByteArray(bytes, 0, bytes.size, options)
    }

    private fun encodePng(bitmap: Bitmap): ByteArray =
        ByteArrayOutputStream().use { out ->
            bitmap.compress(Bitmap.CompressFormat.PNG, 100, out)
            out.toByteArray()
        }

    /**
     * Builds the clip for received content. Images are written to a private
     * cache file and shared through a FileProvider URI; the clipboard grants
     * the pasting app read access. Only the last few images are kept.
     */
    fun clipFor(context: Context, content: ClipContent): ClipData {
        val png = content.png
        if (png == null) {
            val text = content.text.orEmpty()
            return if (content.html != null) ClipData.newHtmlText("Copyyt", text, content.html)
            else ClipData.newPlainText("Copyyt", text)
        }
        val dir = File(context.cacheDir, "clipboard").apply { mkdirs() }
        val file = File(dir, "${UUID.randomUUID()}.png")
        file.writeBytes(png)
        dir.listFiles()
            ?.sortedByDescending { it.lastModified() }
            ?.drop(KEEP_RECEIVED)
            ?.forEach { it.delete() }
        val uri = FileProvider.getUriForFile(context, "${context.packageName}.clipboard", file)
        val clip = ClipData(ClipDescription("Copyyt", arrayOf("image/png")), ClipData.Item(uri))
        content.text?.takeIf { it.isNotEmpty() }?.let { clip.addItem(ClipData.Item(it)) }
        return clip
    }

    /**
     * Reads what the user copied: an image (as a URI to prepare) or text with
     * any formatting. Clipboard reads need window focus on Android 10+.
     */
    fun readClipboard(context: Context): ClipboardRead? {
        val clipboard = context.getSystemService(android.content.ClipboardManager::class.java)
        val clip = clipboard.primaryClip?.takeIf { it.itemCount > 0 } ?: return null
        val item = clip.getItemAt(0)
        val uri = item.uri
        if (uri != null && (clip.description.hasMimeType("image/*") ||
                context.contentResolver.getType(uri)?.startsWith("image/") == true)
        ) {
            return ClipboardRead.Image(uri)
        }
        val text = item.coerceToText(context)?.toString()?.takeIf { it.isNotEmpty() } ?: return null
        return ClipboardRead.Text(text, item.htmlText)
    }
}

sealed interface ClipboardRead {
    data class Image(val uri: Uri) : ClipboardRead
    data class Text(val text: String, val html: String?) : ClipboardRead
}

/** Turns what was read from the clipboard or a share into sendable content. */
fun ClipboardRead.prepare(resolver: ContentResolver): PreparedClip = when (this) {
    is ClipboardRead.Image -> ClipImages.prepare(resolver, uri)
    is ClipboardRead.Text -> PreparedClip(ClipContent(text, html), resized = false)
}
