package com.copyyt.android.app

import android.annotation.SuppressLint
import android.app.PendingIntent
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.service.quicksettings.TileService
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Sends text or an image and finishes; shared by the share sheet and the tile trampoline. */
private fun ComponentActivity.sendAndFinish(read: ClipboardRead?) {
    if (read == null) {
        Toast.makeText(this, "Nothing to send", Toast.LENGTH_SHORT).show()
        finish()
        return
    }
    SyncService.start(this)
    val engine = CopyytApp.engine(this)
    lifecycleScope.launch {
        val result = runCatching {
            withContext(Dispatchers.IO) {
                val prepared = read.prepare(contentResolver)
                engine.sendClip(prepared.content) to prepared.resized
            }
        }
        Toast.makeText(
            this@sendAndFinish,
            result.fold(
                { (count, resized) -> "Copyyt: sent to $count device(s)" + if (resized) " (image resized to send)" else "" },
                { "Copyyt: ${it.message ?: "send failed"}" },
            ),
            Toast.LENGTH_SHORT,
        ).show()
        finish()
    }
}

/** Share → Copyyt for shared text or an image. */
class ShareActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val share = intent?.takeIf { it.action == Intent.ACTION_SEND }
        val image = share?.takeIf { it.type?.startsWith("image/") == true }?.let {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                it.getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java)
            } else {
                @Suppress("DEPRECATION")
                it.getParcelableExtra(Intent.EXTRA_STREAM) as? Uri
            }
        }
        val read = when {
            image != null -> ClipboardRead.Image(image)
            else -> share?.getCharSequenceExtra(Intent.EXTRA_TEXT)?.toString()?.takeIf { it.isNotEmpty() }
                ?.let { ClipboardRead.Text(it, share.getStringExtra(Intent.EXTRA_HTML_TEXT)) }
        }
        sendAndFinish(read)
    }
}

/**
 * Invisible activity launched by the quick-settings tile. It reads the
 * clipboard once it gains window focus, which Android 10+ requires.
 */
class ClipboardSendActivity : ComponentActivity() {
    private var sent = false

    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        if (!hasFocus || sent) return
        sent = true
        sendAndFinish(ClipImages.readClipboard(this))
    }
}

/** Quick-settings tile: one tap sends the current clipboard. */
class SendTileService : TileService() {
    override fun onClick() {
        super.onClick()
        val intent = Intent(this, ClipboardSendActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startActivityAndCollapse(
                PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_IMMUTABLE),
            )
        } else {
            startActivityAndCollapseLegacy(intent)
        }
    }

    // The Intent overload is the only one before Android 14; it is never
    // reached on 14+, where it would throw.
    @SuppressLint("StartActivityAndCollapseDeprecated")
    @Suppress("DEPRECATION")
    private fun startActivityAndCollapseLegacy(intent: Intent) {
        startActivityAndCollapse(intent)
    }
}
