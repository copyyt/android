package com.copyyt.android.app.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.FilterQuality
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.res.imageResource
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.IntSize
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.copyyt.android.R
import com.copyyt.android.sync.PeerInfo
import com.copyyt.android.sync.PendingApproval
import com.copyyt.android.sync.SyncEngine
import com.copyyt.android.sync.SyncState
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Side effects the screens need from the activity. */
class ScreenActions(
    val readClipboard: () -> String?,
    val googleSignInAvailable: Boolean,
    val googleIdToken: suspend () -> String?,
    val copySensitive: (label: String, text: String) -> Unit,
    val toast: (String) -> Unit,
)

/** Runs a blocking engine call off the main thread and reports failures. */
@Composable
private fun rememberRunner(onError: (String) -> Unit): (suspend () -> Unit) -> Unit {
    val scope = rememberCoroutineScope()
    return { block ->
        scope.launch {
            try {
                withContext(Dispatchers.IO) { block() }
            } catch (error: Exception) {
                onError(error.message ?: "Something went wrong")
            }
        }
    }
}

@Composable
fun CopyytApp(engine: SyncEngine, state: SyncState, actions: ScreenActions) {
    val needsName by engine.needsName.collectAsState()
    if (needsName && state != SyncState.SignedOut) {
        Centered { SetName(engine) }
        return
    }
    when (state) {
        SyncState.SignedOut -> Centered { SignIn(engine, actions) }
        SyncState.Starting -> Centered { Busy("Connecting to Copyyt…") }
        is SyncState.NoRoot -> Centered { NoRoot(engine, state, actions) }
        is SyncState.Pairing -> Centered { Pairing(engine, state, actions) }
        is SyncState.WaitingForApproval -> Centered { Waiting(state) }
        SyncState.Revoked -> Centered { Removed(engine, actions) }
        is SyncState.Error -> Centered {
            Header("Something went wrong", state.message)
            Button(onClick = { engine.start() }, modifier = Modifier.fillMaxWidth()) { Text("Try again") }
            SignOutLink(engine)
        }
        is SyncState.Ready -> ReadyShell(engine, state, actions)
    }
}

// ---- Layout helpers ----------------------------------------------------

@Composable
private fun Centered(content: @Composable ColumnScope.() -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 24.dp, vertical = 40.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Brand()
        Spacer(Modifier.height(8.dp))
        content()
    }
}

@Composable
private fun Brand() {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Image(painterResource(R.drawable.ic_logo_color), contentDescription = null, modifier = Modifier.size(32.dp))
        Spacer(Modifier.width(10.dp))
        Text("Copyyt", style = MaterialTheme.typography.headlineSmall, color = MaterialTheme.colorScheme.onBackground)
    }
}

@Composable
private fun Header(title: String, body: String? = null) {
    Text(title, style = MaterialTheme.typography.headlineMedium, color = MaterialTheme.colorScheme.onBackground)
    body?.let { Text(it, style = MaterialTheme.typography.bodyLarge, color = MaterialTheme.colorScheme.onSurfaceVariant) }
}

@Composable
private fun SectionCard(
    modifier: Modifier = Modifier,
    danger: Boolean = false,
    content: @Composable ColumnScope.() -> Unit,
) {
    Card(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        border = BorderStroke(1.dp, if (danger) MaterialTheme.colorScheme.error.copy(alpha = 0.5f) else MaterialTheme.colorScheme.outline),
    ) {
        Column(Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(10.dp), content = content)
    }
}

@Composable
private fun PrimaryButton(text: String, enabled: Boolean = true, onClick: () -> Unit) {
    Button(
        onClick = onClick,
        enabled = enabled,
        modifier = Modifier.fillMaxWidth().height(52.dp),
        shape = RoundedCornerShape(14.dp),
    ) { Text(text, style = MaterialTheme.typography.labelLarge) }
}

@Composable
private fun SecondaryButton(text: String, enabled: Boolean = true, onClick: () -> Unit) {
    OutlinedButton(
        onClick = onClick,
        enabled = enabled,
        modifier = Modifier.fillMaxWidth().height(48.dp),
        shape = RoundedCornerShape(14.dp),
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.primary),
    ) { Text(text, style = MaterialTheme.typography.labelLarge) }
}

@Composable
private fun DangerButton(text: String, enabled: Boolean = true, onClick: () -> Unit) {
    Button(
        onClick = onClick,
        enabled = enabled,
        modifier = Modifier.fillMaxWidth().height(48.dp),
        shape = RoundedCornerShape(14.dp),
        colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error),
    ) { Text(text, style = MaterialTheme.typography.labelLarge) }
}

@Composable
private fun ErrorText(message: String?) {
    message?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodyMedium) }
}

@Composable
private fun Hint(text: String) {
    Text(text, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
}

@Composable
private fun Busy(text: String) {
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        CircularProgressIndicator(modifier = Modifier.size(22.dp), strokeWidth = 2.5.dp)
        Text(text, style = MaterialTheme.typography.bodyLarge)
    }
}

@Composable
private fun CodeField(value: String, onChange: (String) -> Unit, label: String) {
    OutlinedTextField(
        value = value,
        onValueChange = { onChange(it.filter(Char::isDigit).take(6)) },
        label = { Text(label) },
        singleLine = true,
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
        textStyle = MaterialTheme.typography.titleLarge.copy(letterSpacing = 6.sp),
        modifier = Modifier.fillMaxWidth(),
    )
}

@Composable
private fun Fingerprint(value: String) {
    Box(
        Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(14.dp))
            .background(MaterialTheme.colorScheme.primaryContainer)
            .padding(vertical = 18.dp, horizontal = 12.dp),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            value,
            fontFamily = FontFamily.Monospace,
            fontWeight = FontWeight.Bold,
            fontSize = 20.sp,
            letterSpacing = 1.sp,
            color = MaterialTheme.colorScheme.onPrimaryContainer,
            textAlign = TextAlign.Center,
        )
    }
}

@Composable
private fun SignOutLink(engine: SyncEngine) {
    TextButton(onClick = { engine.signOut() }, modifier = Modifier.fillMaxWidth()) { Text("Sign out") }
}

// ---- Signed-out and setup screens ---------------------------------------

@Composable
private fun SignIn(engine: SyncEngine, actions: ScreenActions) {
    var email by rememberSaveable { mutableStateOf("") }
    var code by rememberSaveable { mutableStateOf("") }
    var codeSent by rememberSaveable { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val run = rememberRunner { error = it; busy = false }

    Header("Copy here, paste anywhere", "Sign in with the same account you use in the Copyyt Chrome extension.")
    if (actions.googleSignInAvailable && !codeSent) {
        OutlinedButton(
            onClick = {
                busy = true
                error = null
                run {
                    val token = actions.googleIdToken()
                    if (token != null) engine.signInWithGoogle(token)
                    busy = false
                }
            },
            enabled = !busy,
            modifier = Modifier.fillMaxWidth().height(52.dp),
            shape = RoundedCornerShape(14.dp),
            colors = ButtonDefaults.outlinedButtonColors(containerColor = MaterialTheme.colorScheme.surface),
            border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline),
        ) {
            Image(painterResource(R.drawable.ic_google), contentDescription = null, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(10.dp))
            Text("Continue with Google", style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.onSurface)
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            HorizontalDivider(Modifier.weight(1f))
            Text("  or use your email  ", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            HorizontalDivider(Modifier.weight(1f))
        }
    }
    OutlinedTextField(
        value = email, onValueChange = { email = it }, label = { Text("Email") },
        singleLine = true, enabled = !codeSent,
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Email),
        modifier = Modifier.fillMaxWidth(),
    )
    if (codeSent) {
        Hint("We sent a 6-digit code to $email.")
        CodeField(code, { code = it }, "Code")
    }
    ErrorText(error)
    PrimaryButton(
        text = if (busy) "Please wait…" else if (codeSent) "Sign in" else "Email me a code",
        enabled = !busy && email.isNotBlank() && (!codeSent || code.length == 6),
    ) {
        busy = true
        error = null
        run {
            if (!codeSent) engine.requestCode(email) else engine.verifyCode(email, code.toInt())
            codeSent = true
            busy = false
        }
    }
    if (codeSent) {
        TextButton(onClick = { codeSent = false; code = "" }, modifier = Modifier.fillMaxWidth()) {
            Text("Use a different email")
        }
    }
}

/** One-time step for accounts that don't have a name yet. */
@Composable
private fun SetName(engine: SyncEngine) {
    var name by rememberSaveable { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val run = rememberRunner { error = it; busy = false }
    Header("What should we call you?", "Your name appears on your account in Copyyt. You can use any name you like.")
    OutlinedTextField(
        value = name,
        onValueChange = { if (it.length <= 100) name = it },
        label = { Text("Name") },
        singleLine = true,
        modifier = Modifier.fillMaxWidth(),
    )
    ErrorText(error)
    PrimaryButton(if (busy) "Saving…" else "Continue", enabled = !busy && name.isNotBlank()) {
        busy = true
        error = null
        run { engine.updateName(name); busy = false }
    }
}

@Composable
private fun NoRoot(engine: SyncEngine, state: SyncState.NoRoot, actions: ScreenActions) {
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val run = rememberRunner { error = it; busy = false }
    if (state.canBeFirstDevice) {
        Header("Set up Copyyt", "Your account has no devices yet. Choose where to start.")
        SectionCard {
            Text("Use this phone as your first device", style = MaterialTheme.typography.titleMedium)
            Hint(
                "This phone becomes your account's root: it approves every new device. You'll save a " +
                    "recovery credential in case you lose it.",
            )
            PrimaryButton(if (busy) "Setting up…" else "Set up this phone", enabled = !busy) {
                busy = true
                error = null
                run { engine.setUpAsFirstDevice(); busy = false }
            }
        }
        SectionCard {
            Text("Or start on Chrome", style = MaterialTheme.typography.titleMedium)
            Hint("Install the Copyyt extension, finish its setup, then come back here to pair this phone.")
            SecondaryButton("I've set up Chrome", enabled = !busy) { engine.start() }
        }
        ErrorText(error)
    } else {
        Header(
            "Your account root was removed",
            "New devices can't join until a device becomes the root. Use your offline recovery credential, " +
                "or reset the account if you lost it.",
        )
        RecoveryInput(engine, "Make this phone the root")
        AccountResetCard(engine, actions)
    }
    SignOutLink(engine)
    AccountDeletionLink(engine, actions)
}

@Composable
private fun Pairing(engine: SyncEngine, state: SyncState.Pairing, actions: ScreenActions) {
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val run = rememberRunner { error = it; busy = false }
    Header("Pair with ${state.rootName}", "Open Copyyt on ${state.rootName}. It shows a code for this phone.")
    Fingerprint(state.fingerprint)
    Hint("Check it matches exactly, then type it there to approve this phone. If the codes differ, stop — don't approve it.")
    ErrorText(error)
    PrimaryButton(if (busy) "Please wait…" else "The codes match", enabled = !busy) {
        busy = true
        run { engine.confirmPairing(); busy = false }
    }
    AccountResetLink(engine, actions)
    SignOutLink(engine)
    AccountDeletionLink(engine, actions)
}

@Composable
private fun Waiting(state: SyncState.WaitingForApproval) {
    Header("Approve on ${state.rootName}", "Type this code into Copyyt on ${state.rootName}. This screen updates by itself.")
    Fingerprint(state.fingerprint)
    Busy("Waiting for approval…")
}

@Composable
private fun Removed(engine: SyncEngine, actions: ScreenActions) {
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val run = rememberRunner { error = it; busy = false }
    Header(
        "This phone was removed",
        "It was removed from your account and can't sync. Setting it up again creates a new device you pair like a first install.",
    )
    ErrorText(error)
    PrimaryButton(if (busy) "Setting up…" else "Set up this phone again", enabled = !busy) {
        busy = true
        run { engine.setUpAgain(); busy = false }
    }
    AccountResetLink(engine, actions)
    SignOutLink(engine)
    AccountDeletionLink(engine, actions)
}

// ---- Ready: tabs --------------------------------------------------------

/** Pixel regions of the user-supplied transparent mockup, excluding its incorrect logo. */
private data class MockupIconRegion(val x: Int, val y: Int, val width: Int, val height: Int)

private val refreshIcon = MockupIconRegion(727, 116, 72, 74)
private val connectedIcon = MockupIconRegion(59, 228, 40, 40)

private enum class Tab(val label: String, val icon: MockupIconRegion) {
    Home("Home", MockupIconRegion(112, 1667, 73, 72)),
    Devices("Devices", MockupIconRegion(376, 1667, 90, 72)),
    Account("Account", MockupIconRegion(673, 1667, 76, 72)),
}

@Composable
private fun MockupIcon(region: MockupIconRegion, modifier: Modifier = Modifier) {
    val atlas = ImageBitmap.imageResource(R.drawable.ui_icon_atlas)
    Canvas(modifier) {
        drawImage(
            image = atlas,
            srcOffset = IntOffset(region.x, region.y),
            srcSize = IntSize(region.width, region.height),
            dstSize = IntSize(size.width.toInt(), size.height.toInt()),
            filterQuality = FilterQuality.High,
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ReadyShell(engine: SyncEngine, state: SyncState.Ready, actions: ScreenActions) {
    var tab by rememberSaveable { mutableStateOf(Tab.Home) }
    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            TopAppBar(
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Image(painterResource(R.drawable.ic_logo_color), contentDescription = null, modifier = Modifier.size(26.dp))
                        Spacer(Modifier.width(8.dp))
                        Text("Copyyt", style = MaterialTheme.typography.titleLarge)
                    }
                },
                actions = {
                    IconButton(onClick = { engine.start() }, modifier = Modifier.semantics { contentDescription = "Refresh" }) {
                        MockupIcon(refreshIcon, Modifier.size(25.dp))
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = MaterialTheme.colorScheme.background),
            )
        },
        bottomBar = {
            NavigationBar(containerColor = MaterialTheme.colorScheme.surface) {
                Tab.entries.forEach { item ->
                    val badge = item == Tab.Devices && state.pendingApprovals.isNotEmpty()
                    NavigationBarItem(
                        selected = tab == item,
                        onClick = { tab = item },
                        icon = { MockupIcon(item.icon, Modifier.size(26.dp)) },
                        label = { Text(if (badge) "${item.label} •" else item.label) },
                    )
                }
            }
        },
    ) { padding ->
        Column(
            Modifier
                .padding(padding)
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            when (tab) {
                Tab.Home -> HomeTab(engine, state, actions) { tab = it }
                Tab.Devices -> DevicesTab(engine, state, actions)
                Tab.Account -> AccountTab(engine, state, actions)
            }
        }
    }
}

@Composable
private fun StatusPill(connected: Boolean) {
    val color = if (connected) MaterialTheme.colorScheme.tertiary else MaterialTheme.colorScheme.onSurfaceVariant
    Row(
        Modifier.padding(vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        if (connected) {
            MockupIcon(connectedIcon, Modifier.size(12.dp))
        } else {
            Box(Modifier.size(8.dp).clip(CircleShape).background(color))
        }
        Spacer(Modifier.width(8.dp))
        Text(if (connected) "Connected" else "Reconnecting…", style = MaterialTheme.typography.labelMedium, color = color)
    }
}

@Composable
private fun DeviceTransferIllustration() {
    Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
        Image(
            painter = painterResource(R.drawable.transfer_illustration),
            contentDescription = null,
            modifier = Modifier.width(260.dp).height(130.dp),
            contentScale = ContentScale.Fit,
        )
    }
}

@Composable
private fun HomeTab(engine: SyncEngine, state: SyncState.Ready, actions: ScreenActions, goTo: (Tab) -> Unit) {
    var sending by remember { mutableStateOf(false) }
    val run = rememberRunner { actions.toast(it); sending = false }
    StatusPill(state.connected)
    Header("Copy here, paste anywhere", "Text you copy on your other devices lands on this phone's clipboard automatically.")
    if (state.rootMissing) {
        Banner("Your account root was removed. Existing devices keep syncing, but new ones can't pair.", "Fix") { goTo(Tab.Account) }
    }
    if (state.pendingApprovals.isNotEmpty()) {
        Banner("${state.pendingApprovals.size} device(s) waiting for your approval.", "Review") { goTo(Tab.Devices) }
    }
    if (state.recovery?.exportable == true) {
        Banner("Save your recovery credential so you can recover if you lose this phone.", "Save") { goTo(Tab.Account) }
    }
    DeviceTransferIllustration()
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        HorizontalDivider(color = MaterialTheme.colorScheme.outline)
        Spacer(Modifier.height(6.dp))
        Text("Send to your devices", style = MaterialTheme.typography.titleMedium)
        Hint("Android only lets apps read the clipboard while they're open, so sending is a tap away.")
        Button(
            onClick = {
                val text = actions.readClipboard()
                if (text.isNullOrEmpty()) {
                    actions.toast("Your clipboard has no text")
                    return@Button
                }
                sending = true
                run {
                    val count = engine.sendText(text)
                    actions.toast("Sent to $count device(s)")
                    sending = false
                }
            },
            enabled = !sending,
            modifier = Modifier.fillMaxWidth().height(56.dp),
            shape = RoundedCornerShape(10.dp),
        ) {
            Image(painterResource(R.drawable.send_plane), contentDescription = null, modifier = Modifier.size(20.dp))
            Spacer(Modifier.width(10.dp))
            Text(if (sending) "Sending…" else "Send my clipboard", style = MaterialTheme.typography.labelLarge)
        }
        Hint("Also: Share → Copyyt from any app, or add the “Send clipboard” quick-settings tile.")
    }
    state.lastEvent?.let { Hint(it) }
}

@Composable
private fun Banner(text: String, action: String, onClick: () -> Unit) {
    Row(
        Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(14.dp))
            .background(MaterialTheme.colorScheme.primaryContainer)
            .padding(start = 16.dp, end = 4.dp, top = 6.dp, bottom = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(text, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onPrimaryContainer, modifier = Modifier.weight(1f))
        TextButton(onClick = onClick) { Text(action) }
    }
}

@Composable
private fun DevicesTab(engine: SyncEngine, state: SyncState.Ready, actions: ScreenActions) {
    Header("Devices")
    state.pendingApprovals.forEach { ApprovalCard(engine, it) }
    if (state.pendingApprovals.isEmpty() && state.isRoot) {
        Hint("To add a device, sign in to Copyyt on it. It will appear here to approve.")
    }
    var removing by remember { mutableStateOf<PeerInfo?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    val run = rememberRunner { error = it }
    SectionCard {
        state.peers.forEachIndexed { index, peer ->
            if (index > 0) HorizontalDivider()
            DeviceRow(peer, canRemove = !peer.isSelf) { removing = peer }
        }
        ErrorText(error)
    }
    removing?.let { peer ->
        AlertDialog(
            onDismissRequest = { removing = null },
            title = { Text(if (peer.isRoot) "Remove your account root?" else "Remove ${peer.name}?") },
            text = {
                Text(
                    if (peer.isRoot) {
                        "Only do this if it's lost or you no longer use it. Your other devices keep syncing, but no " +
                            "new device can pair until one of them becomes the root with your recovery credential."
                    } else {
                        "It stops syncing immediately and can only rejoin by being set up and approved again."
                    },
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    removing = null
                    error = null
                    run { engine.removeDevice(peer.deviceId); actions.toast("${peer.name} removed") }
                }) { Text("Remove", color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = { TextButton(onClick = { removing = null }) { Text("Cancel") } },
        )
    }
}

@Composable
private fun DeviceRow(peer: PeerInfo, canRemove: Boolean, onRemove: () -> Unit) {
    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
        Box(
            Modifier.size(40.dp).clip(RoundedCornerShape(12.dp)).background(MaterialTheme.colorScheme.primaryContainer),
            contentAlignment = Alignment.Center,
        ) {
            Icon(
                painterResource(if (peer.platform == "android") R.drawable.ic_phone else R.drawable.ic_laptop),
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(20.dp),
            )
        }
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f)) {
            Text(peer.name, style = MaterialTheme.typography.titleSmall)
            val tags = buildList {
                add(if (peer.platform == "android") "Android" else if (peer.platform == "chrome") "Chrome" else peer.platform)
                if (peer.isSelf) add("This phone")
                if (peer.isRoot) add("Root")
                if (peer.pending) add("Waiting for approval") else if (!peer.trusted) add("Not verified yet")
            }
            Text(tags.joinToString(" · "), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        if (canRemove) {
            TextButton(onClick = onRemove) { Text("Remove", color = MaterialTheme.colorScheme.error) }
        }
    }
}

@Composable
private fun ApprovalCard(engine: SyncEngine, approval: PendingApproval) {
    var code by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val run = rememberRunner { error = it; busy = false }
    SectionCard {
        Text("${approval.name} wants to join", style = MaterialTheme.typography.titleMedium)
        Hint("Type the code shown on that device. Only approve it if it's yours and the code matches.")
        OutlinedTextField(
            value = code,
            onValueChange = { code = it.uppercase().filter { c -> c.isLetterOrDigit() || c == '-' }.take(29) },
            label = { Text("Code from ${approval.name}") },
            singleLine = true,
            textStyle = MaterialTheme.typography.bodyLarge.copy(fontFamily = FontFamily.Monospace),
            modifier = Modifier.fillMaxWidth(),
        )
        ErrorText(error)
        PrimaryButton(if (busy) "Approving…" else "Approve", enabled = !busy && code.isNotBlank()) {
            busy = true
            error = null
            run { engine.approveDevice(approval.deviceId, code); busy = false }
        }
    }
}

@Composable
private fun AccountTab(engine: SyncEngine, state: SyncState.Ready, actions: ScreenActions) {
    Header("Account")
    if (state.rootMissing) {
        Text("Your account root was removed", style = MaterialTheme.typography.titleMedium)
        RecoveryInput(engine, "Make this phone the root")
    }
    state.recovery?.let { recovery ->
        SectionCard {
            Text("Recovery credential", style = MaterialTheme.typography.titleMedium)
            when {
                recovery.exportable -> {
                    Hint(
                        "If you lose this phone, this credential lets another device become the root. Save it " +
                            "offline, like a password manager. Anyone with it can take over your devices.",
                    )
                    RecoveryExport(engine, actions)
                }
                recovery.exported -> Hint("Saved and removed from this phone. Keep your offline copy safe.")
                else -> Hint("Not confirmed by the server yet. Copyyt retries automatically when this phone reconnects.")
            }
        }
    }
    AccountResetCard(engine, actions)
    SignOutLink(engine)
    AccountDeletionLink(engine, actions)
}

@Composable
private fun RecoveryExport(engine: SyncEngine, actions: ScreenActions) {
    var credential by remember { mutableStateOf<String?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    val current = credential
    if (current == null) {
        SecondaryButton("Show recovery credential") {
            credential = runCatching { engine.exportRecoveryCredential() }.getOrElse { error = it.message; null }
        }
    } else {
        Box(
            Modifier.fillMaxWidth().clip(RoundedCornerShape(12.dp)).background(MaterialTheme.colorScheme.surfaceVariant).padding(12.dp),
        ) {
            Text(current, fontFamily = FontFamily.Monospace, fontSize = 11.sp, lineHeight = 15.sp)
        }
        SecondaryButton("Copy") { actions.copySensitive("Copyyt recovery credential", current) }
        PrimaryButton("I've saved it offline") {
            runCatching { engine.confirmRecoverySaved() }
                .onSuccess { credential = null; actions.toast("Recovery credential removed from this phone") }
                .onFailure { error = it.message }
        }
        Hint("Until you confirm, you can show it again.")
    }
    ErrorText(error)
}

@Composable
private fun RecoveryInput(engine: SyncEngine, action: String) {
    var text by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val run = rememberRunner { error = it; busy = false }
    SectionCard {
        Text("Use your recovery credential", style = MaterialTheme.typography.titleMedium)
        Hint("Paste the credential you saved from your root device. It's used once and replaced with a new one.")
        OutlinedTextField(
            value = text,
            onValueChange = { text = it },
            label = { Text("Recovery credential") },
            textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
            minLines = 3,
            modifier = Modifier.fillMaxWidth(),
        )
        ErrorText(error)
        PrimaryButton(if (busy) "Working…" else action, enabled = !busy && text.isNotBlank()) {
            busy = true
            error = null
            run { engine.recoverAsRoot(text); text = ""; busy = false }
        }
    }
}

@Composable
private fun AccountDeletionLink(engine: SyncEngine, actions: ScreenActions) {
    var open by remember { mutableStateOf(false) }
    if (open) AccountDeletionCard(engine, actions) { open = false }
    else TextButton(onClick = { open = true }, modifier = Modifier.fillMaxWidth()) {
        Text("Delete account", color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun AccountDeletionCard(engine: SyncEngine, actions: ScreenActions, onCancel: () -> Unit) {
    var confirming by remember { mutableStateOf(false) }
    var codeSent by remember { mutableStateOf(false) }
    var code by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val run = rememberRunner { error = it; busy = false }
    SectionCard(danger = true) {
        Text("Delete your account", style = MaterialTheme.typography.titleMedium)
        Hint(
            "Permanently deletes your Copyyt account, every device on it and all associated data. " +
                "This can't be undone, and Copyyt stops syncing on all your devices.",
        )
        if (codeSent) {
            CodeField(code, { code = it }, "Code from the email")
            ErrorText(error)
            DangerButton(if (busy) "Deleting…" else "Permanently delete account", enabled = !busy && code.length == 6) {
                busy = true
                error = null
                run { engine.deleteAccount(code.toInt()); actions.toast("Account deleted") }
            }
        } else {
            ErrorText(error)
            OutlinedButton(
                onClick = { confirming = true },
                enabled = !busy,
                modifier = Modifier.fillMaxWidth().height(48.dp),
                shape = RoundedCornerShape(14.dp),
                border = BorderStroke(1.dp, MaterialTheme.colorScheme.error),
            ) { Text(if (busy) "Sending…" else "Email me a deletion code", color = MaterialTheme.colorScheme.error) }
        }
        TextButton(onClick = onCancel, enabled = !busy, modifier = Modifier.fillMaxWidth()) { Text("Cancel") }
    }
    if (confirming) {
        AlertDialog(
            onDismissRequest = { confirming = false },
            title = { Text("Delete your Copyyt account?") },
            text = {
                Text(
                    "Your account, every device and all associated data are permanently deleted. " +
                        "We'll email you a code to confirm.",
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    confirming = false
                    busy = true
                    error = null
                    run { engine.requestAccountDeletionCode(); codeSent = true; busy = false }
                }) { Text("Send code", color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = { TextButton(onClick = { confirming = false }) { Text("Cancel") } },
        )
    }
}

@Composable
private fun AccountResetLink(engine: SyncEngine, actions: ScreenActions) {
    var open by remember { mutableStateOf(false) }
    if (open) AccountResetCard(engine, actions)
    else TextButton(onClick = { open = true }, modifier = Modifier.fillMaxWidth()) {
        Text("Lost your root device or recovery credential?", color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun AccountResetCard(engine: SyncEngine, actions: ScreenActions) {
    var confirming by remember { mutableStateOf(false) }
    var codeSent by remember { mutableStateOf(false) }
    var code by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val run = rememberRunner { error = it; busy = false }
    SectionCard(danger = true) {
        Text("Reset account", style = MaterialTheme.typography.titleMedium)
        Hint(
            "Removes every device, including this one, and invalidates your recovery credential. " +
                "Prefer recovery if you still have the credential.",
        )
        if (codeSent) {
            CodeField(code, { code = it }, "Code from the email")
            ErrorText(error)
            DangerButton(if (busy) "Resetting…" else "Reset and remove all devices", enabled = !busy && code.length == 6) {
                busy = true
                error = null
                run { engine.resetAccount(code.toInt()); actions.toast("Account reset"); busy = false }
            }
        } else {
            ErrorText(error)
            OutlinedButton(
                onClick = { confirming = true },
                enabled = !busy,
                modifier = Modifier.fillMaxWidth().height(48.dp),
                shape = RoundedCornerShape(14.dp),
                border = BorderStroke(1.dp, MaterialTheme.colorScheme.error),
            ) { Text(if (busy) "Sending…" else "Email me a reset code", color = MaterialTheme.colorScheme.error) }
        }
    }
    if (confirming) {
        AlertDialog(
            onDismissRequest = { confirming = false },
            title = { Text("Reset your Copyyt account?") },
            text = {
                Text(
                    "Every device is removed and your recovery credential stops working. You'll set up a new " +
                        "root and pair your devices again. We'll email you a code to confirm.",
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    confirming = false
                    busy = true
                    error = null
                    run { engine.requestAccountResetCode(); codeSent = true; busy = false }
                }) { Text("Send code", color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = { TextButton(onClick = { confirming = false }) { Text("Cancel") } },
        )
    }
}
