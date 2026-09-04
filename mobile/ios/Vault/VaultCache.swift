import Foundation

/// Offline cache: the account crypto material and sealed records (ciphertext
/// only), written with complete file protection and excluded from iCloud backup
/// (mobile-clients spec: offline access + app-level privacy).
final class VaultCache {
    private let fm = FileManager.default

    private var dir: URL {
        let base = fm.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        try? fm.createDirectory(at: base, withIntermediateDirectories: true)
        return base
    }
    private var cryptoUrl: URL { dir.appendingPathComponent("account_crypto.json") }
    private var recordsUrl: URL { dir.appendingPathComponent("records.json") }

    var hasCache: Bool { fm.fileExists(atPath: cryptoUrl.path) }
    var cryptoJson: String? { try? String(contentsOf: cryptoUrl, encoding: .utf8) }
    var recordsJson: String? { try? String(contentsOf: recordsUrl, encoding: .utf8) }

    func save(cryptoJson: String, recordsJson: String) {
        write(cryptoUrl, cryptoJson)
        write(recordsUrl, recordsJson)
    }

    func clear() {
        try? fm.removeItem(at: cryptoUrl)
        try? fm.removeItem(at: recordsUrl)
    }

    private func write(_ url: URL, _ content: String) {
        try? Data(content.utf8).write(to: url, options: [.completeFileProtection, .atomic])
        var mutable = url
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try? mutable.setResourceValues(values)
    }
}
