package au.com.rodoskosmos.vault.autofill

import android.app.assist.AssistStructure
import android.text.InputType
import android.view.View
import android.view.autofill.AutofillId

/** Walks an AssistStructure to locate the username/password fields, their
 * current values, and the page's web domain (for browser autofill). */
object FieldParser {

    data class Fields(
        val username: AutofillId?,
        val password: AutofillId?,
        val webDomain: String?,
        val usernameValue: String?,
        val passwordValue: String?
    )

    fun parse(structure: AssistStructure): Fields {
        var username: AutofillId? = null
        var password: AutofillId? = null
        var usernameValue: String? = null
        var passwordValue: String? = null
        var webDomain: String? = null

        fun visit(node: AssistStructure.ViewNode) {
            node.webDomain?.takeIf { it.isNotBlank() }?.let { webDomain = it }

            val hints = node.autofillHints?.toList().orEmpty()
            val inputType = node.inputType
            val isPasswordType =
                inputType and InputType.TYPE_TEXT_VARIATION_PASSWORD != 0 ||
                    inputType and InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD != 0
            val looksLikePassword =
                hints.contains(View.AUTOFILL_HINT_PASSWORD) || isPasswordType
            val looksLikeUsername =
                hints.contains(View.AUTOFILL_HINT_USERNAME) ||
                    hints.contains(View.AUTOFILL_HINT_EMAIL_ADDRESS) ||
                    inputType and InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS != 0

            if (node.autofillId != null) {
                if (looksLikePassword && password == null) {
                    password = node.autofillId
                    passwordValue = node.text?.toString()
                } else if (looksLikeUsername && username == null) {
                    username = node.autofillId
                    usernameValue = node.text?.toString()
                }
            }
            for (i in 0 until node.childCount) visit(node.getChildAt(i))
        }

        for (i in 0 until structure.windowNodeCount) visit(structure.getWindowNodeAt(i).rootViewNode)
        return Fields(username, password, webDomain, usernameValue, passwordValue)
    }
}
