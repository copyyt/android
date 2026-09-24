package com.copyyt.android.app

import android.Manifest
import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.os.PersistableBundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.credentials.CredentialManager
import androidx.credentials.CustomCredential
import androidx.credentials.GetCredentialRequest
import androidx.credentials.exceptions.GetCredentialCancellationException
import com.google.android.libraries.identity.googleid.GetSignInWithGoogleOption
import com.google.android.libraries.identity.googleid.GoogleIdTokenCredential
import com.copyyt.android.BuildConfig
import com.copyyt.android.app.ui.CopyytApp
import com.copyyt.android.app.ui.CopyytTheme
import com.copyyt.android.app.ui.ScreenActions
import com.copyyt.android.sync.SyncException
import com.copyyt.android.sync.SyncState
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class MainActivity : ComponentActivity() {
    private val notificationPermission =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { }

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        val engine = CopyytApp.engine(this)
        val actions = ScreenActions(
            readClipboard = ::readClipboard,
            googleSignInAvailable = BuildConfig.GOOGLE_SERVER_CLIENT_ID.isNotBlank(),
            googleIdToken = ::googleIdToken,
            copySensitive = ::copySensitive,
            toast = { message -> runOnUiThread { Toast.makeText(this, message, Toast.LENGTH_SHORT).show() } },
        )
        setContent {
            CopyytTheme {
                val state by engine.state.collectAsState()
                LaunchedEffect(state is SyncState.SignedOut) {
                    if (state !is SyncState.SignedOut) {
                        requestNotificationsOnce()
                        SyncService.start(this@MainActivity)
                    }
                }
                CopyytApp(engine, state, actions)
            }
        }
    }

    override fun onResume() {
        super.onResume()
        CopyytApp.engine(this).start()
    }

    private fun requestNotificationsOnce() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }

    /** Reading is only allowed while this activity has focus (Android 10+). */
    private fun readClipboard(): String? =
        getSystemService(ClipboardManager::class.java).primaryClip
            ?.takeIf { it.itemCount > 0 }
            ?.getItemAt(0)
            ?.coerceToText(this)
            ?.toString()

    /** Copies secret text, flagged so Android 13+ hides it from the clipboard preview. */
    private fun copySensitive(label: String, text: String) {
        val clip = ClipData.newPlainText(label, text)
        clip.description.extras = PersistableBundle().apply {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
            } else {
                putBoolean("android.content.extra.IS_SENSITIVE", true)
            }
        }
        getSystemService(ClipboardManager::class.java).setPrimaryClip(clip)
        Toast.makeText(this, "Copied. Paste it into your password manager.", Toast.LENGTH_SHORT).show()
    }

    /**
     * Google sign-in through Credential Manager. The ID token's audience is
     * the server (web) client ID, which the backend verifies. Returns null
     * when the user dismisses the sheet.
     */
    private suspend fun googleIdToken(): String? {
        val option = GetSignInWithGoogleOption.Builder(BuildConfig.GOOGLE_SERVER_CLIENT_ID).build()
        val request = GetCredentialRequest.Builder().addCredentialOption(option).build()
        val result = try {
            withContext(Dispatchers.Main) {
                CredentialManager.create(this@MainActivity).getCredential(this@MainActivity, request)
            }
        } catch (_: GetCredentialCancellationException) {
            return null
        }
        val credential = result.credential
        if (credential is CustomCredential &&
            credential.type == GoogleIdTokenCredential.TYPE_GOOGLE_ID_TOKEN_CREDENTIAL
        ) {
            return GoogleIdTokenCredential.createFrom(credential.data).idToken
        }
        throw SyncException("Google sign-in returned an unexpected credential")
    }
}
