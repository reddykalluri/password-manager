import Foundation
import LocalAuthentication
import Security

/// Face ID / Touch ID gated storage of the vault session key (the exported
/// account key) in the Keychain, protected by a Secure-Enclave-backed access
/// control that requires biometrics and invalidates on biometric-enrolment
/// change (mobile-clients spec: biometric unlock + invalidation).
enum Biometric {
    private static let account = "vault.session-account-key"
    private static let service = "au.com.rodoskosmos.vault"

    static func available() -> Bool {
        LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
    }

    static func isEnabled() -> Bool {
        var query = baseQuery()
        query[kSecReturnData as String] = false
        query[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUIFail
        let status = SecItemCopyMatching(query as CFDictionary, nil)
        return status == errSecSuccess || status == errSecInteractionNotAllowed
    }

    static func enable(accountKeyB64: String) throws {
        disable()
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .biometryCurrentSet, nil
        ) else { throw VaultError.Message(message: "cannot create access control") }

        var query = baseQuery()
        query[kSecValueData as String] = Data(accountKeyB64.utf8)
        query[kSecAttrAccessControl as String] = access
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else { throw VaultError.Message(message: "keychain store failed (\(status))") }
    }

    static func unlock(reason: String = "Unlock Vault") async throws -> String {
        let context = LAContext()
        context.localizedReason = reason
        var query = baseQuery()
        query[kSecReturnData as String] = true
        query[kSecUseAuthenticationContext as String] = context

        var out: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &out)
        guard status == errSecSuccess, let data = out as? Data else {
            throw VaultError.Message(message: "biometric unlock failed (\(status))")
        }
        return String(decoding: data, as: UTF8.self)
    }

    static func disable() {
        SecItemDelete(baseQuery() as CFDictionary)
    }

    private static func baseQuery() -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
    }
}
