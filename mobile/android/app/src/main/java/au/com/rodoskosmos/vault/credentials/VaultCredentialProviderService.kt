package au.com.rodoskosmos.vault.credentials

import android.os.CancellationSignal
import android.os.OutcomeReceiver
import androidx.credentials.exceptions.ClearCredentialException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.provider.BeginCreateCredentialRequest
import androidx.credentials.provider.BeginCreateCredentialResponse
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.credentials.provider.CredentialProviderService
import androidx.credentials.provider.ProviderClearCredentialStateRequest
import au.com.rodoskosmos.vault.VaultManager

/**
 * Credential Manager provider for passkeys (WebAuthn) create + get.
 *
 * NOTE: this is the integration skeleton — it wires the provider entry points to
 * the vault. Completing the FIDO2 ceremonies (building
 * `PublicKeyCredentialEntry`s from stored passkeys, and creating/asserting via a
 * PendingIntent activity) requires on-device testing and is finished there. When
 * the vault holds no passkey for the relying party, the provider yields no
 * entries so platform/other providers are unaffected.
 */
class VaultCredentialProviderService : CredentialProviderService() {

    override fun onBeginGetCredentialRequest(
        request: BeginGetCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginGetCredentialResponse, GetCredentialException>
    ) {
        // With an unlocked vault, map the RP to stored passkeys and return
        // PublicKeyCredentialEntry items (each backed by a PendingIntent that
        // performs the assertion). Locked → an "unlock" authentication action.
        val response = BeginGetCredentialResponse.Builder().build()
        callback.onResult(response)
    }

    override fun onBeginCreateCredentialRequest(
        request: BeginCreateCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginCreateCredentialResponse, CreateCredentialException>
    ) {
        // Offer to create + store a passkey in the vault for the requesting RP.
        val response = BeginCreateCredentialResponse.Builder().build()
        callback.onResult(response)
    }

    override fun onClearCredentialStateRequest(
        request: ProviderClearCredentialStateRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<Void?, ClearCredentialException>
    ) {
        VaultManager.lock()
        callback.onResult(null)
    }
}
