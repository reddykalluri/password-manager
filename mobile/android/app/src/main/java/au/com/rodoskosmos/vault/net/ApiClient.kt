package au.com.rodoskosmos.vault.net

import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONObject

/** Minimal server client. Access tokens live only in memory. */
class ApiClient(var baseUrl: String) {
    private val http = OkHttpClient()
    private val json = "application/json".toMediaType()
    var accessToken: String? = null

    private fun post(path: String, body: JSONObject, auth: Boolean = false): JSONObject {
        val builder = Request.Builder()
            .url("$baseUrl/api/v1$path")
            .post(body.toString().toRequestBody(json))
        if (auth) accessToken?.let { builder.header("Authorization", "Bearer $it") }
        return exec(builder.build())
    }

    private fun get(path: String): JSONObject {
        val builder = Request.Builder().url("$baseUrl/api/v1$path")
        accessToken?.let { builder.header("Authorization", "Bearer $it") }
        return exec(builder.build())
    }

    private fun exec(request: Request): JSONObject {
        http.newCall(request).execute().use { resp ->
            val text = resp.body?.string().orEmpty()
            val obj = if (text.isBlank()) JSONObject() else JSONObject(text)
            if (!resp.isSuccessful) throw ApiException(resp.code, obj.optString("error", "error"), obj)
            return obj
        }
    }

    fun loginStart(username: String, credentialRequest: String): JSONObject =
        post("/auth/login/start", JSONObject().put("username", username).put("credential_request", credentialRequest))

    fun loginFinish(flowId: String, finalization: String, deviceName: String, totp: String?): JSONObject =
        post(
            "/auth/login/finish",
            JSONObject()
                .put("flow_id", flowId)
                .put("credential_finalization", finalization)
                .put("device_name", deviceName)
                .apply { if (totp != null) put("totp_code", totp) }
        )

    fun accountCrypto(): JSONObject = get("/account/crypto")

    fun pull(cursor: Long): JSONObject = get("/sync?cursor=$cursor")

    fun push(record: JSONObject, baseVersion: Long): JSONObject =
        post("/sync/push", JSONObject().put("record", record).put("base_version", baseVersion), auth = true)
}

class ApiException(val status: Int, val code: String, val body: JSONObject) :
    Exception("$status $code")
