package com.psami.copyyt.android

import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import com.psami.copyyt.R
import com.psami.copyyt.sync.SyncState
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch

/**
 * Holds the encrypted socket open so received text is copied automatically.
 * Runs only while signed in; stops itself on sign-out.
 */
class SyncService : Service() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private var watchJob: Job? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        ServiceCompat.startForeground(
            this,
            NOTIFICATION_ID,
            notification("Connecting…"),
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
            } else 0,
        )
        val engine = CopyytApp.engine(this)
        engine.start()
        watchJob?.cancel()
        watchJob = scope.launch {
            engine.state.collectLatest { state ->
                when (state) {
                    // A removed phone keeps the service so "Set up again" can
                    // resume background receiving without restarting it.
                    SyncState.SignedOut -> stopSelf()
                    else -> update(statusText(state))
                }
            }
        }
        return START_STICKY
    }

    private fun statusText(state: SyncState): String = when (state) {
        is SyncState.Ready -> if (state.connected) "Receiving from your devices" else "Reconnecting…"
        is SyncState.Pairing, is SyncState.WaitingForApproval -> "Waiting for pairing"
        is SyncState.NoRoot -> "Waiting for setup"
        SyncState.Revoked -> "This phone was removed from your account"
        is SyncState.Error -> "Paused: ${state.message}"
        else -> "Connecting…"
    }

    private fun update(text: String) {
        getSystemService(android.app.NotificationManager::class.java)
            .notify(NOTIFICATION_ID, notification(text))
    }

    private fun notification(text: String) =
        NotificationCompat.Builder(this, CopyytApp.CHANNEL_SERVICE)
            .setSmallIcon(R.drawable.ic_copyyt)
            .setContentTitle("Copyyt")
            .setContentText(text)
            .setOngoing(true)
            .setContentIntent(
                PendingIntent.getActivity(
                    this, 0, Intent(this, MainActivity::class.java),
                    PendingIntent.FLAG_IMMUTABLE,
                ),
            )
            .build()

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    companion object {
        private const val NOTIFICATION_ID = 1

        fun start(context: Context) {
            ContextCompat.startForegroundService(context, Intent(context, SyncService::class.java))
        }
    }
}
