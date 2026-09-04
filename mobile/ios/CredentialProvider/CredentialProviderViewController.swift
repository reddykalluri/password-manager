import AuthenticationServices
import UIKit

/// AutoFill Credential Provider: supplies password (and passkey) suggestions
/// above the QuickType keyboard in Safari and apps, biometric-gated, with
/// associated-domain matching and an explicit-search fallback
/// (autofill-integration spec: iOS credential provider).
///
/// This is the integration skeleton: it wires the extension entry points to the
/// shared vault. Completing passkey assertions and the QuickType path is done
/// with on-device testing.
class CredentialProviderViewController: ASCredentialProviderViewController {

    /// Provide a credential without UI when the vault is already unlocked and a
    /// single match exists; otherwise ask the host to show the extension UI.
    override func provideCredentialWithoutUserInteraction(
        for credentialIdentity: ASPasswordCredentialIdentity
    ) {
        Task { @MainActor in
            guard VaultManager.shared.unlocked else {
                extensionContext.cancelRequest(
                    withError: NSError(domain: ASExtensionErrorDomain,
                                       code: ASExtensionError.userInteractionRequired.rawValue))
                return
            }
            if let cred = credential(for: credentialIdentity.recordIdentifier) {
                extensionContext.completeRequest(withSelectedCredential: cred)
            } else {
                extensionContext.cancelRequest(
                    withError: NSError(domain: ASExtensionErrorDomain,
                                       code: ASExtensionError.credentialIdentityNotFound.rawValue))
            }
        }
    }

    /// Show the picker (unlock via Face ID if needed, then choose an item).
    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        let domain = serviceIdentifiers.first?.identifier
        Task { @MainActor in
            if !VaultManager.shared.unlocked {
                if let key = try? await Biometric.unlock() {
                    try? VaultManager.shared.unlockBiometric(accountKeyB64: key)
                }
            }
            // A SwiftUI/UIKit list of VaultManager.candidates(for: domain) would be
            // presented here; selecting one calls completeRequest(...).
            _ = domain
        }
    }

    @MainActor
    private func credential(for id: String?) -> ASPasswordCredential? {
        guard let id else { return nil }
        let item = VaultManager.shared.item(id)
        guard let data = item["data"] as? [String: Any],
              data["type"] as? String == "login",
              let user = data["username"] as? String,
              let pass = data["password"] as? String else { return nil }
        return ASPasswordCredential(user: user, password: pass)
    }
}
