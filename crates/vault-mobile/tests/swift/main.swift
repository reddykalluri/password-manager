// Swift binding test: exercises the generated UniFFI bindings against the real
// vault-core library (mobile-clients spec 6.1: binding tests).

import Foundation

func check(_ cond: Bool, _ msg: String) {
    if !cond {
        FileHandle.standardError.write("FAIL: \(msg)\n".data(using: .utf8)!)
        exit(1)
    }
}

// Stateless: password generation and strength.
let params = try! defaultKdfParams()
let pw = try! generatePassword(
    optionsJson: "{\"length\":20,\"lowercase\":true,\"uppercase\":true,\"digits\":true,\"symbols\":true}")
check(pw.count == 20, "generated password length is 20")
let strengthJson = try! ratePasswordStrength(password: pw)
check(strengthJson.contains("score"), "strength json has score")

// Enrol → the object comes back and yields crypto material + one-time recovery.
let vault = try! VaultHandle.enroll(password: "correct horse battery", paramsJson: params)
let crypto = try! vault.accountCrypto()
check(crypto.contains("kdf_params"), "account crypto has kdf_params")
check(vault.takeRecoveryCode() != nil, "recovery code present after enrol")
check(vault.takeRecoveryCode() == nil, "recovery code consumed on read")

// Create → get → search round trip.
let itemJson = """
{"title":"GitHub","data":{"type":"login","username":"octocat","password":"hunter2","uris":[]},\
"notes":"","tags":[],"favorite":false,"custom_fields":[]}
"""
let id = try! vault.createItem(contentJson: itemJson)
let got = try! vault.getItem(id: id)
check(got.contains("GitHub") && got.contains("octocat"), "item round-trips through native core")
check(vault.search(query: "GitHub").count == 1, "search finds the item")

// The synced/cached records must be ciphertext only.
let records = try! vault.records()
check(!records.contains("hunter2"), "records carry no plaintext password")
check(!records.contains("GitHub"), "records carry no plaintext title")

print("SWIFT BINDING TESTS PASSED")
