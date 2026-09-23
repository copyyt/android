package com.psami.copyyt.android

import android.annotation.SuppressLint
import android.app.PendingIntent
import android.content.ClipboardManager
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.service.quicksettings.TileService
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Sends text and finishes; shared by the share sheet and the tile trampoline. */
private fun ComponentActivity.sendAndFinish(text: String?) {
    if (text.isNullOrEmpty()) {
        Toast.makeText(this, "No text to send", Toast.LENGTH_SHORT).show()
        finish()
        return
    }
    SyncService.start(this)
    val engine = CopyytApp.engine(this)
    lifecycleScope.launch {
        val result = runCatching { withContext(Dispatchers.IO) { engine.sendText(text) } }
        Toast.makeText(
            this@sendAndFinish,
            result.fold({ "Copyyt: sent to $it device(s)" }, { "Copyyt: ${it.message ?: "send failed"}" }),
            Toast.LENGTH_SHORT,
        ).show()
        finish()
    }
}

/** Share → Copyyt for any shared text. */
class ShareActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val text = intent?.takeIf { it.action == Intent.ACTION_SEND }
            ?.getCharSequenceExtra(Intent.EXTRA_TEXT)?.toString()
        sendAndFinish(text)
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
        val text = getSystemService(ClipboardManager::class.java).primaryClip
            ?.takeIf { it.itemCount > 0 }
            ?.getItemAt(0)
            ?.coerceToText(this)
            ?.toString()
        sendAndFinish(text)
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
