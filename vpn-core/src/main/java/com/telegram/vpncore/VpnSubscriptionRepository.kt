package com.telegram.vpncore

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import org.json.JSONArray
import org.json.JSONObject

/**
 * Stores VPN subscriptions in EncryptedSharedPreferences — the subscription URL
 * commonly embeds a per-user panel token, so it's treated like the config secrets.
 */
class VpnSubscriptionRepository(context: Context) {

    // Held past construction (lazy prefs + migration) — keep the application context, not
    // whatever (possibly Activity) context the caller handed us.
    private val context: Context = context.applicationContext

    companion object {
        private const val PREFS_FILE = "vpn_subscriptions"
        private const val KEY_SUBS = "subscriptions"
    }

    private val prefs by lazy {
        val legacyJson = takeLegacyPlainJsonIfAny()
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        val encrypted = EncryptedSharedPreferences.create(
            context,
            PREFS_FILE,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
        if (legacyJson != null) {
            encrypted.edit().putString(KEY_SUBS, legacyJson).apply()
        }
        encrypted
    }

    /**
     * Before this repo switched to EncryptedSharedPreferences, subscriptions were stored in a
     * plain SharedPreferences file with the same name — same underlying XML file, since
     * EncryptedSharedPreferences.create() just wraps getSharedPreferences(PREFS_FILE, ...) too.
     * If we opened that file with EncryptedSharedPreferences straight away, it would try to
     * decrypt the old plaintext JSON and fail. So: read the raw plaintext value first via a
     * plain SharedPreferences handle (still works, the file is plain XML at this point), then
     * clear the file so EncryptedSharedPreferences.create() starts from an empty/consistent
     * state and the plaintext copy doesn't linger on disk. Returns null if there's nothing to
     * migrate (fresh install, or migration already ran).
     */
    private fun takeLegacyPlainJsonIfAny(): String? {
        val plain = context.getSharedPreferences(PREFS_FILE, Context.MODE_PRIVATE)
        val legacyJson = plain.getString(KEY_SUBS, null)
        if (legacyJson.isNullOrBlank() || legacyJson == "[]") return null
        // Clear synchronously (commit, not apply) — EncryptedSharedPreferences.create() below
        // must see an empty file, not a pending-write race with the plaintext value still there.
        plain.edit().clear().commit()
        return legacyJson
    }

    fun getAll(): List<VpnSubscription> {
        val raw = prefs.getString(KEY_SUBS, "[]") ?: "[]"
        return try {
            val arr = JSONArray(raw)
            (0 until arr.length()).map { deserialize(arr.getJSONObject(it)) }
        } catch (e: Exception) {
            emptyList()
        }
    }

    fun save(sub: VpnSubscription) {
        val list = getAll().toMutableList()
        val idx = list.indexOfFirst { it.id == sub.id }
        if (idx >= 0) list[idx] = sub else list.add(sub)
        persist(list)
    }

    fun delete(id: String) {
        persist(getAll().filter { it.id != id })
    }

    fun getById(id: String): VpnSubscription? = getAll().firstOrNull { it.id == id }

    private fun persist(list: List<VpnSubscription>) {
        val arr = JSONArray()
        list.forEach { arr.put(serialize(it)) }
        prefs.edit().putString(KEY_SUBS, arr.toString()).apply()
    }

    private fun serialize(s: VpnSubscription): JSONObject = JSONObject().apply {
        put("id", s.id)
        put("name", s.name)
        put("url", s.url)
        put("lastUpdated", s.lastUpdated)
        put("configIds", JSONArray(s.configIds))
        put("hasUsage", s.hasUsage)
        put("uploadBytes", s.uploadBytes)
        put("downloadBytes", s.downloadBytes)
        put("totalBytes", s.totalBytes)
        put("expireAt", s.expireAt)
        put("updateIntervalHours", s.updateIntervalHours)
        put("webPageUrl", s.webPageUrl)
        put("supportUrl", s.supportUrl)
    }

    private fun deserialize(j: JSONObject): VpnSubscription {
        val idsArr = j.optJSONArray("configIds") ?: JSONArray()
        val ids = (0 until idsArr.length()).map { idsArr.getString(it) }
        return VpnSubscription(
            id = j.optString("id", java.util.UUID.randomUUID().toString()),
            name = j.optString("name", ""),
            url = j.optString("url", ""),
            lastUpdated = j.optLong("lastUpdated", 0L),
            configIds = ids,
            hasUsage = j.optBoolean("hasUsage", false),
            uploadBytes = j.optLong("uploadBytes", 0L),
            downloadBytes = j.optLong("downloadBytes", 0L),
            totalBytes = j.optLong("totalBytes", 0L),
            expireAt = j.optLong("expireAt", 0L),
            updateIntervalHours = j.optInt("updateIntervalHours", 0),
            webPageUrl = j.optString("webPageUrl", ""),
            supportUrl = j.optString("supportUrl", "")
        )
    }
}
