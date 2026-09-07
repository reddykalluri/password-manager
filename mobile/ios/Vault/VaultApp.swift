import SwiftUI

@main
struct VaultApp: App {
    @StateObject private var manager = VaultManager.shared
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            ZStack {
                if manager.unlocked {
                    VaultView()
                } else {
                    UnlockView()
                }
                // App-switcher / background privacy mask.
                if scenePhase != .active {
                    PrivacyCover()
                }
            }
            .environmentObject(manager)
        }
    }
}

private struct PrivacyCover: View {
    var body: some View {
        ZStack {
            Rectangle().fill(.ultraThinMaterial).ignoresSafeArea()
            Image(systemName: "lock.shield").font(.system(size: 48)).foregroundStyle(.secondary)
        }
    }
}

// MARK: - Unlock

struct UnlockView: View {
    @EnvironmentObject var manager: VaultManager
    @AppStorage("instance_url") private var instance = "https://"
    @AppStorage("username") private var username = ""
    @State private var password = ""
    @State private var totp = ""
    @State private var error: String?
    @State private var busy = false

    var body: some View {
        Form {
            Section("Instance") {
                TextField("https://vault.example.com", text: $instance)
                    .textInputAutocapitalization(.never).keyboardType(.URL)
                TextField("Username", text: $username).textInputAutocapitalization(.never)
            }
            Section("Master password") {
                SecureField("Master password", text: $password)
                TextField("2FA code (if enabled)", text: $totp).keyboardType(.numberPad)
            }
            if let error { Text(error).foregroundStyle(.red) }
            Button(busy ? "Unlocking…" : "Unlock") { unlock() }.disabled(busy)
            if Biometric.available() && Biometric.isEnabled() && manager.hasCache {
                Button("Unlock with Face ID") { unlockBiometric() }
            }
        }
    }

    private func unlock() {
        busy = true; error = nil
        Task {
            do {
                try await manager.unlockOnline(instanceUrl: instance, username: username, password: password, totp: totp.isEmpty ? nil : totp)
            } catch {
                // Fall back to the offline cache.
                do { try manager.unlockOffline(password: password) }
                catch { self.error = error.localizedDescription }
            }
            busy = false
        }
    }

    private func unlockBiometric() {
        Task {
            do {
                let key = try await Biometric.unlock()
                try manager.unlockBiometric(accountKeyB64: key)
            } catch { self.error = error.localizedDescription }
        }
    }
}

// MARK: - Vault (adaptive list/detail)

struct VaultView: View {
    @EnvironmentObject var manager: VaultManager
    @State private var query = ""
    @State private var selection: String?

    private var ids: [String] { query.isEmpty ? manager.listActive() : manager.search(query) }

    var body: some View {
        NavigationSplitView {
            List(ids, id: \.self, selection: $selection) { id in
                let item = manager.item(id)
                VStack(alignment: .leading) {
                    Text(item["title"] as? String ?? "")
                    if let data = item["data"] as? [String: Any], let u = data["username"] as? String, !u.isEmpty {
                        Text(u).font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
            .searchable(text: $query)
            .navigationTitle("Vault")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) { SyncBadge(state: manager.syncState) }
                ToolbarItem(placement: .topBarLeading) { Button("Lock") { manager.lock() } }
            }
        } detail: {
            if let selection { ItemDetailView(id: selection) }
            else { ContentUnavailableView("Select an item", systemImage: "key") }
        }
        .task { await manager.sync() }
    }
}

struct ItemDetailView: View {
    @EnvironmentObject var manager: VaultManager
    let id: String
    @State private var reveal = false

    var body: some View {
        let item = manager.item(id)
        let data = item["data"] as? [String: Any] ?? [:]
        Form {
            Section(item["title"] as? String ?? "") {
                if data["type"] as? String == "login" {
                    LabeledContent("Username", value: data["username"] as? String ?? "")
                    HStack {
                        Text("Password")
                        Spacer()
                        Text(reveal ? (data["password"] as? String ?? "") : "••••••••")
                            .font(.system(.body, design: .monospaced))
                        Button(reveal ? "Hide" : "Show") { reveal.toggle() }
                    }
                    if let totp = data["totp"] as? String, !totp.isEmpty {
                        LabeledContent("TOTP secret", value: totp)
                    }
                }
            }
        }
    }
}

private struct SyncBadge: View {
    let state: VaultManager.SyncState
    var label: String {
        switch state {
        case .synced: return "Synced"
        case .pending: return "Pending"
        case .error: return "Sync error"
        case .offline: return "Offline"
        }
    }
    var body: some View { Text(label).font(.caption).foregroundStyle(.secondary) }
}
