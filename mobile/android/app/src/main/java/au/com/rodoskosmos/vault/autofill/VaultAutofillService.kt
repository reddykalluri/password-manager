package au.com.rodoskosmos.vault.autofill

import android.app.assist.AssistStructure
import android.os.CancellationSignal
import android.service.autofill.*
import android.view.autofill.AutofillId
import android.view.autofill.AutofillValue
import android.widget.RemoteViews
import au.com.rodoskosmos.vault.VaultManager
import org.json.JSONObject

/**
 * System AutofillService: inline fill suggestions in native apps and browsers,
 * biometric-gated when locked, with save capture. Web domains are matched via
 * the item URI rules; app packages are matched to domains through Digital Asset
 * Links (verified links preferred; unverified associations are flagged).
 */
class VaultAutofillService : AutofillService() {

    override fun onFillRequest(
        request: FillRequest,
        cancellationSignal: CancellationSignal,
        callback: FillCallback
    ) {
        val structure = request.fillContexts.lastOrNull()?.structure
        val parsed = structure?.let { FieldParser.parse(it) }
        if (parsed == null || (parsed.username == null && parsed.password == null)) {
            callback.onSuccess(null)
            return
        }

        val webDomain = parsed.webDomain
        val pkg = structure.activityComponent?.packageName

        // Determine the origin to match against (web domain, or the app package
        // resolved to a domain via Digital Asset Links).
        val matchUrl = when {
            webDomain != null -> "https://$webDomain"
            pkg != null -> DigitalAssetLinks.domainForPackage(this, pkg)?.let { "https://$it" }
            else -> null
        }

        val response = FillResponse.Builder()

        if (!VaultManager.isUnlocked) {
            // Offer an "unlock" entry that opens the app (biometric prompt there).
            response.addDataset(unlockDataset(parsed))
        } else if (matchUrl != null) {
            for (id in VaultManager.candidatesFor(matchUrl)) {
                val item = VaultManager.getItem(id)
                response.addDataset(loginDataset(parsed, item))
            }
        }

        // Offer to save what the user types.
        val saveIds = listOfNotNull(parsed.username, parsed.password).toTypedArray()
        if (saveIds.isNotEmpty()) {
            response.setSaveInfo(
                SaveInfo.Builder(
                    SaveInfo.SAVE_DATA_TYPE_USERNAME or SaveInfo.SAVE_DATA_TYPE_PASSWORD,
                    saveIds
                ).build()
            )
        }
        callback.onSuccess(response.build())
    }

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        val structure = request.fillContexts.lastOrNull()?.structure
        val parsed = structure?.let { FieldParser.parse(it) }
        val username = parsed?.usernameValue.orEmpty()
        val password = parsed?.passwordValue.orEmpty()
        val domain = parsed?.webDomain
        if (password.isNotBlank() && domain != null && VaultManager.isUnlocked) {
            // Dedupe/update is handled in VaultManager (base domain + username).
            VaultManager.createLogin(domain, username, password, "https://$domain")
        }
        callback.onSuccess()
    }

    private fun loginDataset(fields: FieldParser.Fields, item: JSONObject): Dataset {
        val data = item.optJSONObject("data") ?: JSONObject()
        val presentation = RemoteViews(packageName, android.R.layout.simple_list_item_1).apply {
            setTextViewText(android.R.id.text1, item.optString("title"))
        }
        val builder = Dataset.Builder(presentation)
        fields.username?.let { builder.setValue(it, AutofillValue.forText(data.optString("username"))) }
        fields.password?.let { builder.setValue(it, AutofillValue.forText(data.optString("password"))) }
        return builder.build()
    }

    private fun unlockDataset(fields: FieldParser.Fields): Dataset {
        val presentation = RemoteViews(packageName, android.R.layout.simple_list_item_1).apply {
            setTextViewText(android.R.id.text1, "Unlock Vault to fill")
        }
        val builder = Dataset.Builder(presentation)
        // Present a placeholder; selecting it opens the app to unlock.
        fields.username?.let { builder.setValue(it, AutofillValue.forText("")) }
        return builder.build()
    }
}
