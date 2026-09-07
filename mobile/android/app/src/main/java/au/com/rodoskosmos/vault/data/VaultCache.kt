package au.com.rodoskosmos.vault.data

import android.content.Context
import androidx.security.crypto.EncryptedFile
import androidx.security.crypto.MasterKey
import java.io.File

/**
 * Encrypted-at-rest local cache (offline access): the account crypto material
 * and sealed item records, encrypted with an Android Keystore master key. Only
 * ciphertext + wrapped keys are stored; the vault is never written in plaintext.
 */
class VaultCache(private val context: Context) {

    private val masterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()

    private fun encFile(name: String): EncryptedFile =
        EncryptedFile.Builder(
            context,
            File(context.filesDir, name),
            masterKey,
            EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
        ).build()

    fun save(cryptoJson: String, recordsJson: String) {
        write("account_crypto.enc", cryptoJson)
        write("records.enc", recordsJson)
    }

    fun cryptoJson(): String? = readOrNull("account_crypto.enc")
    fun recordsJson(): String? = readOrNull("records.enc")
    fun hasCache(): Boolean = File(context.filesDir, "account_crypto.enc").exists()

    fun clear() {
        File(context.filesDir, "account_crypto.enc").delete()
        File(context.filesDir, "records.enc").delete()
    }

    private fun write(name: String, content: String) {
        val f = File(context.filesDir, name)
        if (f.exists()) f.delete()
        encFile(name).openFileOutput().use { it.write(content.toByteArray()) }
    }

    private fun readOrNull(name: String): String? {
        val f = File(context.filesDir, name)
        if (!f.exists()) return null
        return encFile(name).openFileInput().use { it.readBytes().toString(Charsets.UTF_8) }
    }
}
