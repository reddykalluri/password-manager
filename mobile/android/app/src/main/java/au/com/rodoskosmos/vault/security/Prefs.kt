package au.com.rodoskosmos.vault.security

import android.content.Context
import android.os.SystemClock
import android.util.Base64

/** Non-secret preferences plus the biometric-wrapped session key. The wrapped
 * key is bound to the current boot: after a reboot it is discarded so a
 * master-password unlock is required again (mobile-clients spec). */
object Prefs {
    private fun prefs(ctx: Context) = ctx.getSharedPreferences("vault", Context.MODE_PRIVATE)

    // Approximate boot epoch (ms), stable within a boot, changes across reboots.
    private fun bootId(): Long = (System.currentTimeMillis() - SystemClock.elapsedRealtime()) / 1000

    fun instanceUrl(ctx: Context): String? = prefs(ctx).getString("instance_url", null)
    fun setInstanceUrl(ctx: Context, url: String) =
        prefs(ctx).edit().putString("instance_url", url.trimEnd('/')).apply()

    fun username(ctx: Context): String? = prefs(ctx).getString("username", null)
    fun setUsername(ctx: Context, u: String) = prefs(ctx).edit().putString("username", u).apply()

    fun storeWrappedSessionKey(ctx: Context, iv: ByteArray, ct: ByteArray) {
        prefs(ctx).edit()
            .putString("sk_iv", b64(iv))
            .putString("sk_ct", b64(ct))
            .putLong("sk_boot", bootId())
            .apply()
    }

    fun wrappedSessionKey(ctx: Context): Pair<ByteArray, ByteArray>? {
        val p = prefs(ctx)
        val iv = p.getString("sk_iv", null) ?: return null
        val ct = p.getString("sk_ct", null) ?: return null
        if (p.getLong("sk_boot", -1) != bootId()) {
            clear(ctx)
            return null
        }
        return unb64(iv) to unb64(ct)
    }

    fun clear(ctx: Context) {
        prefs(ctx).edit().remove("sk_iv").remove("sk_ct").remove("sk_boot").apply()
    }

    private fun b64(b: ByteArray) = Base64.encodeToString(b, Base64.NO_WRAP)
    private fun unb64(s: String) = Base64.decode(s, Base64.NO_WRAP)
}
