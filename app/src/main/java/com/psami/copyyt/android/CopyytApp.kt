package com.psami.copyyt.android

import android.Manifest
import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import com.psami.copyyt.BuildConfig
import com.psami.copyyt.R
import com.psami.copyyt.net.CopyytApi
import com.psami.copyyt.store.IdentityStore
import com.psami.copyyt.store.ProcessedItems
import com.psami.copyyt.store.SessionStore
import com.psami.copyyt.sync.SyncEngine
import com.psami.copyyt.sync.SyncPlatform
import com.psami.copyyt.trust.TrustStore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import java.time.Instant

class CopyytApp : Application() {
    lateinit var engine: SyncEngine
        private set

    override fun onCreate() {
        super.onCreate()
        createChannels()
        val storage = KeystoreStorage(this)
        engine = SyncEngine(
            api = CopyytApi(BuildConfig.API_URL),
            socketUrl = BuildConfig.SOCKET_URL,
            socketFactory = { url, token, listener -> SocketIoConnection(url, token, listener) },
            sessions = SessionStore(storage),
            identities = IdentityStore(storage),
            trust = TrustStore(storage),
            processed = ProcessedItems(storage),
            platform = AndroidPlatform(this),
            scope = CoroutineScope(SupervisorJob() + Dispatchers.IO),
        )
    }

    private fun createChannels() {
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(
            NotificationChannel(CHANNEL_SERVICE, "Sync connection", NotificationManager.IMPORTANCE_MIN)
                .apply { description = "Keeps the encrypted connection to your devices open" },
        )
        manager.createNotificationChannel(
            NotificationChannel(CHANNEL_RECEIVED, "Received clipboard", NotificationManager.IMPORTANCE_DEFAULT)
                .apply { description = "Shown when text from another device is copied" },
        )
    }

    companion object {
        const val CHANNEL_SERVICE = "sync-service"
        const val CHANNEL_RECEIVED = "clipboard-received"
        const val NOTIFICATION_RECEIVED = 2

        fun engine(context: Context): SyncEngine = (context.applicationContext as CopyytApp).engine
    }
}

private class AndroidPlatform(private val context: Context) : SyncPlatform {
    override val deviceName: String =
        "Android · ${Build.MANUFACTURER.replaceFirstChar { it.uppercase() }} ${Build.MODEL}"
    override val appVersion: String = BuildConfig.VERSION_NAME

    override fun now(): Instant = Instant.now()

    override fun writeClipboard(text: String) {
        val clipboard = context.getSystemService(ClipboardManager::class.java)
        // Android 10+ restricts clipboard *reads* to the focused app; writes
        // from the foreground sync service are permitted.
        clipboard.setPrimaryClip(ClipData.newPlainText("Copyyt", text))
    }

    override fun notifyReceived(sourceName: String, charCount: Int) {
        // Content is never placed in the notification: only its origin and size.
        val notification = NotificationCompat.Builder(context, CopyytApp.CHANNEL_RECEIVED)
            .setSmallIcon(R.drawable.ic_copyyt)
            .setContentTitle("Copied from $sourceName")
            .setContentText("$charCount characters are on your clipboard")
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
            .setAutoCancel(true)
            .build()
        val allowed = Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU ||
            context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) ==
            PackageManager.PERMISSION_GRANTED
        if (allowed) {
            NotificationManagerCompat.from(context).notify(CopyytApp.NOTIFICATION_RECEIVED, notification)
        }
    }
}
