package au.com.rodoskosmos.vault

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.*
import androidx.compose.material3.adaptive.layout.AnimatedPane
import androidx.compose.material3.adaptive.layout.ListDetailPaneScaffoldRole
import androidx.compose.material3.adaptive.navigation.NavigableListDetailPaneScaffold
import androidx.compose.material3.adaptive.navigation.rememberListDetailPaneScaffoldNavigator
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import au.com.rodoskosmos.vault.security.BiometricSession
import au.com.rodoskosmos.vault.security.Prefs
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject

/**
 * Root: unlock gate, then an adaptive list/detail vault (single column on
 * phones, two panes on large screens / unfolded devices).
 */
@Composable
fun VaultApp(activity: FragmentActivity) {
    var unlocked by remember { mutableStateOf(VaultManager.isUnlocked) }
    if (!unlocked) UnlockScreen(activity) { unlocked = true } else VaultScreen(activity) { unlocked = false }
}

@Composable
private fun UnlockScreen(activity: FragmentActivity, onUnlocked: () -> Unit) {
    val scope = rememberCoroutineScope()
    val biometric = remember { BiometricSession(activity) }
    var instance by remember { mutableStateOf(Prefs.instanceUrl(activity) ?: "https://") }
    var username by remember { mutableStateOf(Prefs.username(activity) ?: "") }
    var password by remember { mutableStateOf("") }
    var totp by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }

    Column(Modifier.fillMaxSize().padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("Unlock Vault", style = MaterialTheme.typography.headlineSmall)
        OutlinedTextField(instance, { instance = it }, label = { Text("Instance URL") }, singleLine = true)
        OutlinedTextField(username, { username = it }, label = { Text("Username") }, singleLine = true)
        OutlinedTextField(
            password, { password = it }, label = { Text("Master password") },
            visualTransformation = PasswordVisualTransformation(), singleLine = true
        )
        OutlinedTextField(
            totp, { totp = it }, label = { Text("2FA code (if enabled)") },
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number), singleLine = true
        )
        error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
        Button(
            enabled = !busy,
            onClick = {
                busy = true; error = null
                scope.launch {
                    try {
                        withContext(Dispatchers.IO) {
                            Prefs.setInstanceUrl(activity, instance)
                            Prefs.setUsername(activity, username)
                            VaultManager.unlockOnline(instance, username, password, totp.ifBlank { null })
                        }
                        onUnlocked()
                    } catch (e: Exception) {
                        // Fall back to offline cache when the network is unavailable.
                        try {
                            withContext(Dispatchers.IO) { VaultManager.unlockOffline(password) }
                            onUnlocked()
                        } catch (_: Exception) {
                            error = e.message ?: "unlock failed"
                        }
                    } finally { busy = false }
                }
            }
        ) { Text(if (busy) "Unlocking…" else "Unlock") }

        if (biometric.available() && biometric.isEnabled() && VaultManager.hasCache) {
            TextButton(onClick = {
                scope.launch {
                    try {
                        val key = biometric.unlock()
                        withContext(Dispatchers.IO) { VaultManager.unlockBiometric(key) }
                        onUnlocked()
                    } catch (e: Exception) { error = e.message }
                }
            }) { Text("Unlock with biometrics") }
        }
    }
}

@Composable
private fun VaultScreen(activity: FragmentActivity, onLock: () -> Unit) {
    val scope = rememberCoroutineScope()
    val navigator = rememberListDetailPaneScaffoldNavigator<String>()
    var query by remember { mutableStateOf("") }
    var ids by remember { mutableStateOf(VaultManager.listActive()) }

    LaunchedEffect(query) {
        ids = if (query.isBlank()) VaultManager.listActive() else VaultManager.search(query)
    }
    LaunchedEffect(Unit) { withContext(Dispatchers.IO) { VaultManager.sync() } }

    NavigableListDetailPaneScaffold(
        navigator = navigator,
        listPane = {
            AnimatedPane {
                Column(Modifier.fillMaxSize()) {
                    TopAppBar(
                        title = { Text("Vault") },
                        actions = { TextButton(onClick = { VaultManager.lock(); onLock() }) { Text("Lock") } }
                    )
                    OutlinedTextField(
                        query, { query = it }, Modifier.fillMaxWidth().padding(12.dp),
                        label = { Text("Search") }, singleLine = true
                    )
                    SyncBadge(VaultManager.syncState)
                    LazyColumn(Modifier.fillMaxSize()) {
                        items(ids) { id ->
                            val item = remember(id) { VaultManager.getItem(id) }
                            ListItem(
                                headlineContent = { Text(item.optString("title")) },
                                supportingContent = {
                                    Text(item.optJSONObject("data")?.optString("username").orEmpty())
                                },
                                modifier = Modifier.clickable {
                                    navigator.navigateTo(ListDetailPaneScaffoldRole.Detail, id)
                                }
                            )
                        }
                    }
                }
            }
        },
        detailPane = {
            AnimatedPane {
                navigator.currentDestination?.contentKey?.let { id -> ItemDetail(id) }
                    ?: Box(Modifier.fillMaxSize(), contentAlignment = androidx.compose.ui.Alignment.Center) {
                        Text("Select an item")
                    }
            }
        }
    )
}

@Composable
private fun ItemDetail(id: String) {
    val item = remember(id) { VaultManager.getItem(id) }
    val data = item.optJSONObject("data") ?: JSONObject()
    Column(Modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(item.optString("title"), style = MaterialTheme.typography.headlineSmall)
        if (data.optString("type") == "login") {
            SecretRow("Username", data.optString("username"), secret = false)
            SecretRow("Password", data.optString("password"), secret = true)
            val totp = data.optString("totp", "")
            if (totp.isNotBlank()) SecretRow("TOTP secret", totp, secret = true)
        }
    }
}

@Composable
private fun SecretRow(label: String, value: String, secret: Boolean) {
    var revealed by remember { mutableStateOf(!secret) }
    ListItem(
        overlineContent = { Text(label) },
        headlineContent = { Text(if (revealed) value else "••••••••") },
        trailingContent = {
            Row {
                if (secret) TextButton(onClick = { revealed = !revealed }) { Text(if (revealed) "Hide" else "Show") }
            }
        }
    )
}

@Composable
private fun SyncBadge(state: SyncState) {
    val label = when (state) {
        SyncState.SYNCED -> "Synced"
        SyncState.PENDING -> "Pending sync"
        SyncState.ERROR -> "Sync error"
        SyncState.OFFLINE -> "Offline"
    }
    AssistChip(onClick = {}, label = { Text(label) }, modifier = Modifier.padding(horizontal = 12.dp))
}
