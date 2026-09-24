package com.copyyt.android

import com.copyyt.android.sync.ClipContent
import com.copyyt.android.sync.ClipboardBundle
import com.copyyt.android.sync.ClipboardBundleException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ClipboardBundleTest {
    private val png = byteArrayOf(0x89.toByte(), 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 9)

    private fun rejects(json: String) {
        val failure = runCatching { ClipboardBundle.decode(json.toByteArray()) }.exceptionOrNull()
        assertTrue("expected rejection of $json", failure is ClipboardBundleException)
    }

    @Test
    fun roundTripsTextFormattingAndImages() {
        val decoded = ClipboardBundle.decode(
            ClipboardBundle.encode(ClipContent("héllo 👋", "<b>héllo</b>", png)),
        )
        assertEquals("héllo 👋", decoded.text)
        assertEquals("<b>héllo</b>", decoded.html)
        assertTrue(decoded.png!!.contentEquals(png))
    }

    @Test
    fun usesTheExtensionsJsonShape() {
        assertEquals(
            """{"version":1,"representations":[{"mime":"text/plain","encoding":"utf-8","data":"hi"}]}""",
            ClipboardBundle.encode(ClipContent(text = "hi")).toString(Charsets.UTF_8),
        )
    }

    @Test
    fun rejectsWhatTheExtensionRejects() {
        val plain = """{"mime":"text/plain","encoding":"utf-8","data":"x"}"""
        rejects("""{"version":1,"representations":[{"mime":"text/html","encoding":"utf-8","data":"x"}]}""")
        rejects("""{"version":1,"representations":[$plain,$plain]}""")
        rejects("""{"version":"1","representations":[$plain]}""")
        rejects("""{"version":2,"representations":[$plain]}""")
        rejects("""{"version":1,"representations":[]}""")
        rejects("""{"version":1,"representations":[$plain],"extra":true}""")
        rejects("""{"version":1,"representations":[{"mime":"text/plain","encoding":"utf-8","data":"x","x":1}]}""")
        rejects("""{"version":1,"representations":[{"mime":"image/png","encoding":"base64","data":"aGVsbG8="}]}""")
        rejects("""{"version":1,"representations":[{"mime":"image/jpeg","encoding":"base64","data":"aGVsbG8="}]}""")
    }

    @Test
    fun refusesToEncodeHtmlWithoutText() {
        val failure = runCatching { ClipboardBundle.encode(ClipContent(html = "<b>x</b>")) }.exceptionOrNull()
        assertTrue(failure is ClipboardBundleException)
    }
}
