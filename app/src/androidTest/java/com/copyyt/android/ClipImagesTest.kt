package com.copyyt.android

import android.content.ClipboardManager
import android.graphics.Bitmap
import android.graphics.Color
import android.net.Uri
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.copyyt.android.app.ClipImages
import com.copyyt.android.sync.ClipContent
import com.copyyt.android.sync.ClipboardBundle
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayOutputStream
import java.io.File
import kotlin.random.Random

@RunWith(AndroidJUnit4::class)
class ClipImagesTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    /** A noisy image compresses badly, like a photo, so it won't fit as-is. */
    private fun noisyPng(width: Int, height: Int): ByteArray {
        val random = Random(7)
        val pixels = IntArray(width * height) { Color.rgb(random.nextInt(256), random.nextInt(256), random.nextInt(256)) }
        val bitmap = Bitmap.createBitmap(pixels, width, height, Bitmap.Config.ARGB_8888)
        return ByteArrayOutputStream().use { out ->
            bitmap.compress(Bitmap.CompressFormat.PNG, 100, out)
            out.toByteArray()
        }
    }

    private fun fileUri(bytes: ByteArray): Uri {
        val file = File(context.cacheDir, "test-input.png").apply { writeBytes(bytes) }
        return Uri.fromFile(file)
    }

    @Test
    fun aSmallPngIsSentUnchanged() {
        val png = noisyPng(64, 64)
        val prepared = ClipImages.prepare(context.contentResolver, fileUri(png))
        assertTrue(prepared.content.png!!.contentEquals(png))
        assertTrue(!prepared.resized)
    }

    @Test
    fun aLargeImageIsShrunkUntilItFitsTheRelay() {
        val png = noisyPng(1600, 1200)
        assertTrue("fixture must be too large", !ClipboardBundle.fits(ClipContent(png = png)))

        val prepared = ClipImages.prepare(context.contentResolver, fileUri(png))

        assertTrue(prepared.resized)
        assertTrue(ClipboardBundle.fits(prepared.content))
        assertTrue(ClipboardBundle.hasPngSignature(prepared.content.png!!))
    }

    @Test
    fun aReceivedImageIsReadableFromTheClipboard() {
        val png = noisyPng(32, 32)
        val clip = ClipImages.clipFor(context, ClipContent(text = "caption", png = png))
        InstrumentationRegistry.getInstrumentation().runOnMainSync {
            context.getSystemService(ClipboardManager::class.java).setPrimaryClip(clip)
        }
        val uri = clip.getItemAt(0).uri
        assertEquals("${context.packageName}.clipboard", uri.authority)
        assertTrue(clip.description.hasMimeType("image/png"))
        val read = context.contentResolver.openInputStream(uri)!!.use { it.readBytes() }
        assertTrue(read.contentEquals(png))
        assertEquals("caption", clip.getItemAt(1).text.toString())
    }

    @Test
    fun formattedTextBecomesAnHtmlClip() {
        val clip = ClipImages.clipFor(context, ClipContent(text = "bold", html = "<b>bold</b>"))
        assertEquals("<b>bold</b>", clip.getItemAt(0).htmlText)
        assertEquals("bold", clip.getItemAt(0).text.toString())
    }
}
