import Foundation

/// Minimal server client (URLSession). Access tokens live only in memory.
final class ApiClient {
    let baseUrl: String
    var accessToken: String?
    private let session = URLSession(configuration: .ephemeral)

    init(baseUrl: String) { self.baseUrl = baseUrl }

    func loginStart(username: String, credentialRequest: String) async throws -> [String: Any] {
        try await post("/auth/login/start", ["username": username, "credential_request": credentialRequest])
    }

    func loginFinish(flowId: String, finalization: String, deviceName: String, totp: String?) async throws -> [String: Any] {
        var body: [String: Any] = [
            "flow_id": flowId, "credential_finalization": finalization, "device_name": deviceName
        ]
        if let totp { body["totp_code"] = totp }
        return try await post("/auth/login/finish", body)
    }

    func accountCrypto() async throws -> [String: Any] { try await get("/account/crypto", auth: true) }
    func pull(cursor: Int) async throws -> [String: Any] { try await get("/sync?cursor=\(cursor)", auth: true) }
    func push(record: [String: Any], baseVersion: Int) async throws -> [String: Any] {
        try await post("/sync/push", ["record": record, "base_version": baseVersion], auth: true)
    }

    private func post(_ path: String, _ body: [String: Any], auth: Bool = false) async throws -> [String: Any] {
        var req = URLRequest(url: URL(string: "\(baseUrl)/api/v1\(path)")!)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if auth, let t = accessToken { req.setValue("Bearer \(t)", forHTTPHeaderField: "Authorization") }
        req.httpBody = try JSONSerialization.data(withJSONObject: body)
        return try await run(req)
    }

    private func get(_ path: String, auth: Bool = false) async throws -> [String: Any] {
        var req = URLRequest(url: URL(string: "\(baseUrl)/api/v1\(path)")!)
        if auth, let t = accessToken { req.setValue("Bearer \(t)", forHTTPHeaderField: "Authorization") }
        return try await run(req)
    }

    private func run(_ req: URLRequest) async throws -> [String: Any] {
        let (data, resp) = try await session.data(for: req)
        let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] ?? [:]
        if let http = resp as? HTTPURLResponse, !(200..<300).contains(http.statusCode) {
            throw VaultError.Message(message: obj["error"] as? String ?? "http \(http.statusCode)")
        }
        return obj
    }
}
