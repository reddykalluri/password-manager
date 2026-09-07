package au.com.rodoskosmos.vault

import android.content.Context
import au.com.rodoskosmos.vault.data.VaultCache
import au.com.rodoskosmos.vault.net.ApiClient
import org.json.JSONArray
import org.json.JSONObject
import uniffi.vault_mobile.VaultHandle
import uniffi.vault_mobile.benchmarkKdf
import uniffi.vault_mobile.defaultKdfParams
import uniffi.vault_mobile.generatePassword
import uniffi.vault_mobile.opaqueLoginFinish
import uniffi.vault_mobile.opaqueLoginStart
import uniffi.vault_mobile.ratePasswordStrength

enum class SyncState { SYNCED, PENDING, ERROR, OFFLINE }

/**
 * Process-global vault session shared by the UI, the AutofillService, and the
 * CredentialProvider. Holds the unlocked native vault (UniFFI) in memory only.
 */
object VaultManager {
    private var vault: VaultHandle? = null
    private var api: ApiClient? = null
    private lateinit var cache: VaultCache
    private var cursor: Long = 0
    private val baseVersions = HashMap<String, Long>()
    var syncState: SyncState = SyncState.SYNCED
        private set

    fun init(context: Context) {
        if (!::cache.isInitialized) cache = VaultCache(context.applicationContext)
    }

    val isUnlocked: Boolean get() = vault != null
    val hasCache: Boolean get() = ::cache.isInitialized && cache.hasCache()

    // --- unlock paths ------------------------------------------------------

    /** Online unlock: OPAQUE login, fetch crypto + records, open the vault. */
    fun unlockOnline(instanceUrl: String, username: String, password: String, totp: String?) {
        val client = ApiClient(instanceUrl.trimEnd('/'))
        val ls = JSONObject(opaqueLoginStart(password))
        val start = client.loginStart(username, ls.getString("message"))
        val finalization = opaqueLoginFinish(ls.getString("state"), password, start.getString("credential_response"))
        val outcome = client.loginFinish(start.getString("flow_id"), finalization, "Android", totp)
        if (!outcome.has("access_token")) throw IllegalStateException("second factor required")
        client.accessToken = outcome.getString("access_token")

        val crypto = client.accountCrypto()
        val pulled = client.pull(0)
        cursor = pulled.getLong("cursor")
        val records = pulled.getJSONArray("records")
        rememberBaseVersions(records)
        vault = VaultHandle.unlock(password, crypto.toString(), records.toString())
        api = client
        cache.save(crypto.toString(), records.toString())
        syncState = SyncState.SYNCED
    }

    /** Offline unlock from the encrypted cache with the master password. */
    fun unlockOffline(password: String) {
        val crypto = cache.cryptoJson() ?: error("no cache")
        val records = cache.recordsJson() ?: "[]"
        vault = VaultHandle.unlock(password, crypto, records)
        rememberBaseVersions(JSONArray(records))
        syncState = SyncState.OFFLINE
    }

    /** Biometric unlock: the account key comes from the Keystore, crypto and
     * records from the encrypted cache. */
    fun unlockBiometric(accountKeyB64: String) {
        val crypto = cache.cryptoJson() ?: error("no cache")
        val records = cache.recordsJson() ?: "[]"
        vault = VaultHandle.unlockWithAccountKey(accountKeyB64, crypto, records)
        rememberBaseVersions(JSONArray(records))
        syncState = SyncState.OFFLINE
    }

    fun exportAccountKey(): String = requireVault().exportAccountKey()

    fun lock() {
        vault?.destroy()
        vault = null
        api = null
        baseVersions.clear()
        cursor = 0
    }

    // --- items -------------------------------------------------------------

    private fun requireVault(): VaultHandle = vault ?: error("locked")

    fun listActive(): List<String> = requireVault().listActive()
    fun search(query: String): List<String> = requireVault().search(query)
    fun candidatesFor(url: String): List<String> = requireVault().candidatesFor(url)
    fun getItem(id: String): JSONObject = JSONObject(requireVault().getItem(id))

    /** Distinct hostnames across stored login URIs (for Digital Asset Links). */
    fun itemDomains(): List<String> {
        val out = LinkedHashSet<String>()
        for (id in listActive()) {
            val uris = getItem(id).optJSONObject("data")?.optJSONArray("uris") ?: continue
            for (i in 0 until uris.length()) {
                hostOf(uris.getJSONObject(i).optString("value"))?.let { out.add(it) }
            }
        }
        return out.toList()
    }

    private fun hostOf(url: String): String? = try {
        java.net.URI(if (url.contains("://")) url else "https://$url").host
    } catch (e: Exception) { null }

    fun createLogin(title: String, username: String, password: String, uri: String): String {
        val content = JSONObject()
            .put("title", title)
            .put("data", JSONObject()
                .put("type", "login").put("username", username).put("password", password)
                .put("uris", JSONArray().put(JSONObject().put("value", uri).put("match_rule", "base_domain"))))
            .put("notes", "").put("tags", JSONArray()).put("favorite", false)
            .put("custom_fields", JSONArray())
        val id = requireVault().createItem(content.toString())
        pushChanges()
        return id
    }

    fun updateItem(id: String, content: JSONObject) {
        requireVault().updateItem(id, content.toString())
        pushChanges()
    }

    fun generatePassword(): String =
        generatePassword("""{"length":20,"lowercase":true,"uppercase":true,"digits":true,"symbols":true}""")

    fun strength(pw: String): JSONObject = JSONObject(ratePasswordStrength(pw))

    fun negotiateParams(): String = try { benchmarkKdf(500.0) } catch (e: Exception) { defaultKdfParams() }

    // --- sync --------------------------------------------------------------

    fun sync() {
        val client = api ?: run { syncState = SyncState.OFFLINE; return }
        try {
            val pulled = client.pull(cursor)
            val records = pulled.getJSONArray("records")
            for (i in 0 until records.length()) {
                val rec = records.getJSONObject(i)
                requireVault().applyRecord(rec.toString())
                baseVersions[rec.getString("id")] = rec.getLong("version")
            }
            cursor = pulled.getLong("cursor")
            pushChanges()
            cache.save(cache.cryptoJson() ?: "{}", requireVault().records())
            syncState = SyncState.SYNCED
        } catch (e: Exception) {
            syncState = SyncState.ERROR
        }
    }

    private fun pushChanges() {
        val client = api ?: run { syncState = SyncState.PENDING; return }
        val records = JSONArray(requireVault().records())
        for (i in 0 until records.length()) {
            val rec = records.getJSONObject(i)
            val id = rec.getString("id")
            val base = baseVersions[id] ?: 0
            if (rec.getLong("version") == base) continue
            try {
                val res = client.push(rec, base)
                baseVersions[id] = res.getLong("new_version")
                cursor = maxOf(cursor, res.getLong("cursor"))
            } catch (e: Exception) {
                syncState = SyncState.PENDING
            }
        }
        cache.save(cache.cryptoJson() ?: "{}", requireVault().records())
    }

    private fun rememberBaseVersions(records: JSONArray) {
        for (i in 0 until records.length()) {
            val rec = records.getJSONObject(i)
            baseVersions[rec.getString("id")] = rec.getLong("version")
        }
    }
}
