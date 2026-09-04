package au.com.rodoskosmos.vault.security

import androidx.fragment.app.FragmentActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlin.coroutines.suspendCoroutine

/**
 * Wraps the vault session key (the exported account key) with an Android
 * Keystore AES key that requires Class-3 biometric authentication. The key is
 * `setInvalidatedByBiometricEnrollment(true)`, so enrolling a new fingerprint
 * invalidates it and forces a master-password unlock (mobile-clients spec:
 * biometric invalidation). A boot check forces re-auth after restart.
 */
class BiometricSession(private val activity: FragmentActivity) {

    private val keystore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    fun available(): Boolean =
        BiometricManager.from(activity)
            .canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) ==
            BiometricManager.BIOMETRIC_SUCCESS

    fun isEnabled(): Boolean = keystore.containsAlias(KEY_ALIAS) &&
        Prefs.wrappedSessionKey(activity) != null

    private fun getOrCreateKey(): SecretKey {
        (keystore.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        gen.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setUserAuthenticationRequired(true)
                .setInvalidatedByBiometricEnrollment(true)
                .build()
        )
        return gen.generateKey()
    }

    /** Enable biometric unlock by wrapping the exported account key (base64). */
    suspend fun enable(accountKeyB64: String) {
        val cipher = Cipher.getInstance(TRANSFORM).apply { init(Cipher.ENCRYPT_MODE, getOrCreateKey()) }
        authenticate(cipher, "Enable biometric unlock")
        val ct = cipher.doFinal(accountKeyB64.toByteArray())
        Prefs.storeWrappedSessionKey(activity, cipher.iv, ct)
    }

    fun disable() {
        if (keystore.containsAlias(KEY_ALIAS)) keystore.deleteEntry(KEY_ALIAS)
        Prefs.clear(activity)
    }

    /** Unlock: prompt for biometrics and unwrap the account key (base64). */
    suspend fun unlock(): String {
        val (iv, ct) = Prefs.wrappedSessionKey(activity) ?: error("biometric not enabled")
        val cipher = Cipher.getInstance(TRANSFORM).apply {
            init(Cipher.DECRYPT_MODE, getOrCreateKey(), GCMParameterSpec(128, iv))
        }
        authenticate(cipher, "Unlock Vault")
        return cipher.doFinal(ct).toString(Charsets.UTF_8)
    }

    private suspend fun authenticate(cipher: Cipher, title: String): Unit = suspendCoroutine { cont ->
        val prompt = BiometricPrompt(
            activity,
            ContextCompat.getMainExecutor(activity),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    cont.resume(Unit)
                }
                override fun onAuthenticationError(code: Int, msg: CharSequence) {
                    cont.resumeWithException(RuntimeException(msg.toString()))
                }
            }
        )
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setNegativeButtonText("Use master password")
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .build()
        prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))
    }

    companion object {
        private const val KEY_ALIAS = "vault_session_key"
        private const val TRANSFORM = "AES/GCM/NoPadding"
    }
}
