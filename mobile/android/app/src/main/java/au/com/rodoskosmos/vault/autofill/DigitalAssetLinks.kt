package au.com.rodoskosmos.vault.autofill

import android.content.Context
import android.content.pm.PackageManager
import au.com.rodoskosmos.vault.VaultManager
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONArray
import java.security.MessageDigest

/**
 * Digital Asset Links: verify that a native app package is authorised by a
 * domain (the domain's `/.well-known/assetlinks.json` lists the app's package
 * and signing-certificate fingerprint). Unverified app-to-domain links are not
 * treated as matches (autofill-integration spec: Android system autofill).
 */
object DigitalAssetLinks {
    private val http = OkHttpClient()

    /** The first of the user's item domains that verifies for `pkg`, or null. */
    fun domainForPackage(context: Context, pkg: String): String? {
        val fingerprint = signingFingerprint(context, pkg) ?: return null
        return VaultManager.itemDomains().firstOrNull { verifies(it, pkg, fingerprint) }
    }

    fun verifies(domain: String, pkg: String, sha256Fingerprint: String): Boolean {
        return try {
            val url = "https://$domain/.well-known/assetlinks.json"
            http.newCall(Request.Builder().url(url).build()).execute().use { resp ->
                if (!resp.isSuccessful) return false
                val statements = JSONArray(resp.body?.string().orEmpty())
                for (i in 0 until statements.length()) {
                    val target = statements.getJSONObject(i).optJSONObject("target") ?: continue
                    if (target.optString("namespace") != "android_app") continue
                    if (target.optString("package_name") != pkg) continue
                    val fps = target.optJSONArray("sha256_cert_fingerprints") ?: continue
                    for (j in 0 until fps.length()) {
                        if (fps.getString(j).equals(sha256Fingerprint, ignoreCase = true)) return true
                    }
                }
                false
            }
        } catch (e: Exception) {
            false
        }
    }

    @Suppress("DEPRECATION", "PackageManagerGetSignatures")
    private fun signingFingerprint(context: Context, pkg: String): String? {
        return try {
            val pm = context.packageManager
            val info = pm.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES)
            val sig = info.signingInfo?.apkContentsSigners?.firstOrNull() ?: return null
            val md = MessageDigest.getInstance("SHA-256").digest(sig.toByteArray())
            md.joinToString(":") { "%02X".format(it) }
        } catch (e: Exception) {
            null
        }
    }
}
