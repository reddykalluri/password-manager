import Foundation

/// Process-global vault session shared by the app and the Credential Provider
/// extension. Holds the unlocked native vault (UniFFI) in memory only.
@MainActor
final class VaultManager: ObservableObject {
    static let shared = VaultManager()

    enum SyncState { case synced, pending, error, offline }

    @Published private(set) var unlocked = false
    @Published private(set) var syncState: SyncState = .synced

    private var vault: VaultHandle?
    private var api: ApiClient?
    private let cache = VaultCache()
    private var cursor: Int = 0
    private var baseVersions: [String: Int] = [:]

    var hasCache: Bool { cache.hasCache }

    // MARK: unlock paths

    func unlockOnline(instanceUrl: String, username: String, password: String, totp: String?) async throws {
        let client = ApiClient(baseUrl: instanceUrl.trimmingTrailingSlash())
        let ls = try jsonObject(opaqueLoginStart(password: password))
        let start = try await client.loginStart(username: username, credentialRequest: ls["message"] as! String)
        let finalization = try opaqueLoginFinish(
            stateB64: ls["state"] as! String, password: password,
            responseB64: start["credential_response"] as! String)
        let outcome = try await client.loginFinish(
            flowId: start["flow_id"] as! String, finalization: finalization,
            deviceName: "iOS", totp: totp)
        guard let token = outcome["access_token"] as? String else { throw VaultError.Message(message: "second factor required") }
        client.accessToken = token

        let crypto = try await client.accountCrypto()
        let pulled = try await client.pull(cursor: 0)
        cursor = pulled["cursor"] as! Int
        let records = pulled["records"] as! [[String: Any]]
        rememberBaseVersions(records)
        let cryptoStr = jsonString(crypto)
        let recordsStr = jsonString(records)
        vault = try VaultHandle.unlock(password: password, cryptoJson: cryptoStr, recordsJson: recordsStr)
        api = client
        cache.save(cryptoJson: cryptoStr, recordsJson: recordsStr)
        syncState = .synced
        unlocked = true
    }

    func unlockOffline(password: String) throws {
        guard let crypto = cache.cryptoJson else { throw VaultError.Message(message: "no cache") }
        let records = cache.recordsJson ?? "[]"
        vault = try VaultHandle.unlock(password: password, cryptoJson: crypto, recordsJson: records)
        rememberBaseVersions(jsonArray(records))
        syncState = .offline
        unlocked = true
    }

    func unlockBiometric(accountKeyB64: String) throws {
        guard let crypto = cache.cryptoJson else { throw VaultError.Message(message: "no cache") }
        let records = cache.recordsJson ?? "[]"
        vault = try VaultHandle.unlockWithAccountKey(accountKeyB64: accountKeyB64, cryptoJson: crypto, recordsJson: records)
        rememberBaseVersions(jsonArray(records))
        syncState = .offline
        unlocked = true
    }

    func exportAccountKey() throws -> String { try requireVault().exportAccountKey() }

    func lock() {
        vault = nil
        api = nil
        baseVersions.removeAll()
        cursor = 0
        unlocked = false
    }

    // MARK: items

    private func requireVault() throws -> VaultHandle {
        guard let v = vault else { throw VaultError.Message(message: "locked") }
        return v
    }

    func listActive() -> [String] { (try? requireVault().listActive()) ?? [] }
    func search(_ q: String) -> [String] { (try? requireVault().search(query: q)) ?? [] }
    func candidates(for url: String) -> [String] { (try? requireVault().candidatesFor(url: url)) ?? [] }
    func item(_ id: String) -> [String: Any] {
        guard let json = try? requireVault().getItem(id: id) else { return [:] }
        return (try? jsonObject(json)) ?? [:]
    }

    func generatePassword() -> String {
        (try? Vault.generatePassword(optionsJson: #"{"length":20,"lowercase":true,"uppercase":true,"digits":true,"symbols":true}"#)) ?? ""
    }

    func sync() async {
        guard let client = api else { syncState = .offline; return }
        do {
            let pulled = try await client.pull(cursor: cursor)
            for rec in pulled["records"] as! [[String: Any]] {
                try requireVault().applyRecord(recordJson: jsonString(rec))
                baseVersions[rec["id"] as! String] = (rec["version"] as! Int)
            }
            cursor = pulled["cursor"] as! Int
            try await pushChanges()
            syncState = .synced
        } catch {
            syncState = .error
        }
    }

    private func pushChanges() async throws {
        guard let client = api else { syncState = .pending; return }
        let records = jsonArray(try requireVault().records())
        for rec in records {
            let id = rec["id"] as! String
            let base = baseVersions[id] ?? 0
            if (rec["version"] as! Int) == base { continue }
            let res = try await client.push(record: rec, baseVersion: base)
            baseVersions[id] = res["new_version"] as! Int
            cursor = max(cursor, res["cursor"] as! Int)
        }
        cache.save(cryptoJson: cache.cryptoJson ?? "{}", recordsJson: try requireVault().records())
    }

    private func rememberBaseVersions(_ records: [[String: Any]]) {
        for rec in records { baseVersions[rec["id"] as! String] = (rec["version"] as! Int) }
    }
}

// MARK: - JSON helpers

func jsonObject(_ s: String) throws -> [String: Any] {
    try JSONSerialization.jsonObject(with: Data(s.utf8)) as! [String: Any]
}
func jsonArray(_ s: String) -> [[String: Any]] {
    (try? JSONSerialization.jsonObject(with: Data(s.utf8)) as? [[String: Any]]) ?? []
}
func jsonString(_ any: Any) -> String {
    let data = try! JSONSerialization.data(withJSONObject: any)
    return String(decoding: data, as: UTF8.self)
}

extension String {
    func trimmingTrailingSlash() -> String {
        hasSuffix("/") ? String(dropLast()) : self
    }
}
