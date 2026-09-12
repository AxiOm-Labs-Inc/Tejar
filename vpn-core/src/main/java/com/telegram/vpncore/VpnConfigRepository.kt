package com.telegram.vpncore

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import org.json.JSONArray
import org.json.JSONObject

/**
 * Persists VPN configurations in EncryptedSharedPreferences.
 * Stores a JSON array of serialized VpnConfig objects.
 */
class VpnConfigRepository(context: Context) {

    private val appContext: Context = context.applicationContext

    companion object {
        private const val PREFS_FILE = "vpn_configs"
        private const val KEY_CONFIGS = "configs"
        private const val KEY_ACTIVE_ID = "active_config_id"
        private const val KEY_VPN_RUNNING = "vpn_running"
        private const val KEY_ENERGY_SAVING = "energy_saving"
        private const val KEY_AUTO_SELECT = "auto_select"
        private const val KEY_PINNED_ID = "pinned_config_id"
        private const val KEY_DEFAULTS_FORCED = "defaults_forced_152"

        // Auto-reconnect is owned by the settings screen and lives in its own preferences
        // file. Both names are duplicated from VpnSettingsActivity on purpose — the migration
        // below has to reach that file, and they must stay in step.
        private const val SETTINGS_PREFS_FILE = "vpn_settings"
        private const val SETTINGS_KEY_AUTO_RECONNECT = "auto_reconnect"
        private const val KEY_LATENCY = "latency"
    }

    private val prefs by lazy {
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        EncryptedSharedPreferences.create(
            context,
            PREFS_FILE,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    // ─────────────────────────── CRUD ────────────────────────────

    fun getAll(): List<VpnConfig> {
        val raw = prefs.getString(KEY_CONFIGS, "[]") ?: "[]"
        val arr = try {
            JSONArray(raw)
        } catch (e: Exception) {
            return emptyList()
        }
        // Skip only the entries that fail to parse — a single corrupt config used to fail the
        // whole array, and since save() persists getAll() + the edit, that silently wiped every
        // other saved config on the next save.
        val result = mutableListOf<VpnConfig>()
        for (i in 0 until arr.length()) {
            try {
                result.add(deserialize(arr.getJSONObject(i)))
            } catch (e: Exception) {
                // drop this one entry only
            }
        }
        return result
    }

    fun save(config: VpnConfig) {
        val list = getAll().toMutableList()
        val idx = list.indexOfFirst { it.id == config.id }
        if (idx >= 0) list[idx] = config else list.add(config)
        persist(list)
    }

    fun delete(id: String) {
        persist(getAll().filter { it.id != id })
        if (getActiveId() == id) clearActive()
    }

    fun getActive(): VpnConfig? {
        val activeId = getActiveId() ?: return null
        return getAll().firstOrNull { it.id == activeId }
    }

    fun setActive(id: String?) {
        prefs.edit().apply {
            if (id == null) remove(KEY_ACTIVE_ID) else putString(KEY_ACTIVE_ID, id)
        }.apply()
    }

    fun clearActive() = setActive(null)

    fun setVpnRunning(running: Boolean) {
        prefs.edit().putBoolean(KEY_VPN_RUNNING, running).apply()
    }

    fun isVpnRunning(): Boolean = prefs.getBoolean(KEY_VPN_RUNNING, false)

    fun setEnergySaving(enabled: Boolean) {
        prefs.edit().putBoolean(KEY_ENERGY_SAVING, enabled).apply()
    }

    // The default covers a fresh install; after the user touches the switch their choice is
    // stored and read back here. The one exception is [applyForcedDefaultsOnce], which runs
    // a single time on upgrade and overwrites this.
    fun isEnergySaving(): Boolean = prefs.getBoolean(KEY_ENERGY_SAVING, true)

    /**
     * One-time migration: turns Auto-select, Energy Saving and Auto-reconnect on for everyone.
     *
     * Deliberately overrides an explicit "off" as well, not just the never-touched case — the
     * two are indistinguishable in storage anyway (both are simply a missing key), and the
     * point of the change was a single predictable starting state. After this runs once, the
     * switches behave normally again: whatever the user sets is kept.
     */
    fun applyForcedDefaultsOnce() {
        if (prefs.getBoolean(KEY_DEFAULTS_FORCED, false)) return
        prefs.edit()
            .putBoolean(KEY_ENERGY_SAVING, true)
            .putBoolean(KEY_AUTO_SELECT, true)
            .putBoolean(KEY_DEFAULTS_FORCED, true)
            .apply()
        appContext.getSharedPreferences(SETTINGS_PREFS_FILE, Context.MODE_PRIVATE)
            .edit()
            .putBoolean(SETTINGS_KEY_AUTO_RECONNECT, true)
            .apply()
    }

    fun setAutoSelect(enabled: Boolean) {
        prefs.edit().putBoolean(KEY_AUTO_SELECT, enabled).apply()
    }

    fun isAutoSelect(): Boolean = prefs.getBoolean(KEY_AUTO_SELECT, true)

    /**
     * The server the user picked by hand, if any.
     *
     * Auto-select keeps this one instead of chasing the fastest, until it stops answering —
     * otherwise the next round of measurements would drag the user off the location they
     * deliberately chose.
     */
    fun setPinnedId(id: String?) {
        prefs.edit().apply {
            if (id == null) remove(KEY_PINNED_ID) else putString(KEY_PINNED_ID, id)
        }.apply()
    }

    fun getPinnedId(): String? = prefs.getString(KEY_PINNED_ID, null)

    // ───────────────────────── Latency ───────────────────────────
    // Persisted so a measurement survives leaving the screen and restarting the app;
    // keyed by config id, in milliseconds, -1 meaning the server did not answer.

    fun saveLatency(latency: Map<String, Int>) {
        val obj = JSONObject()
        latency.forEach { (id, ms) -> obj.put(id, ms) }
        prefs.edit().putString(KEY_LATENCY, obj.toString()).apply()
    }

    fun getLatency(): Map<String, Int> {
        val raw = prefs.getString(KEY_LATENCY, null) ?: return emptyMap()
        return try {
            val obj = JSONObject(raw)
            buildMap {
                obj.keys().forEach { key -> put(key, obj.getInt(key)) }
            }
        } catch (e: Exception) {
            emptyMap()
        }
    }

    // ─────────────────────────── I/O ─────────────────────────────

    private fun persist(configs: List<VpnConfig>) {
        val arr = JSONArray()
        configs.forEach { arr.put(serialize(it)) }
        prefs.edit().putString(KEY_CONFIGS, arr.toString()).apply()
    }

    private fun getActiveId(): String? = prefs.getString(KEY_ACTIVE_ID, null)

    // ────────────────────── Serialization ────────────────────────

    private fun serialize(c: VpnConfig): JSONObject = JSONObject().apply {
        put("id", c.id)
        put("name", c.name)
        put("protocol", c.protocol.name)
        put("address", c.address)
        put("port", c.port)
        put("uuid", c.uuid)
        put("password", c.password)
        put("encryption", c.encryption)
        put("flow", c.flow)
        put("alterId", c.alterId)
        put("network", c.network.name)
        put("path", c.path)
        put("host", c.host)
        put("serviceName", c.serviceName)
        put("security", c.security.name)
        put("sni", c.sni)
        put("fingerprint", c.fingerprint)
        put("publicKey", c.publicKey)
        put("shortId", c.shortId)
        put("spiderX", c.spiderX)
        put("ssMethod", c.ssMethod)
        // Hysteria2 / Naive fields used to be missing here: the link parsed correctly but the
        // stored copy lost its obfs password and http username, so every config reloaded from
        // disk dialled without them and the server never answered.
        put("obfsPassword", c.obfsPassword)
        put("upMbps", c.upMbps)
        put("downMbps", c.downMbps)
        put("username", c.username)
        put("allowInsecure", c.allowInsecure)
        put("rawLink", c.rawLink)
        put("rawOutbound", c.rawOutbound)
        put("rawType", c.rawType)
        put("rawDependencies", c.rawDependencies)
    }

    private fun deserialize(j: JSONObject): VpnConfig = VpnConfig(
        id = j.optString("id", java.util.UUID.randomUUID().toString()),
        name = j.optString("name"),
        protocol = VpnProtocol.valueOf(j.getString("protocol")),
        address = j.getString("address"),
        port = j.getInt("port"),
        uuid = j.optString("uuid"),
        password = j.optString("password"),
        encryption = j.optString("encryption", "none"),
        flow = j.optString("flow"),
        alterId = j.optInt("alterId", 0),
        network = NetworkType.valueOf(j.optString("network", "TCP")),
        path = j.optString("path"),
        host = j.optString("host"),
        serviceName = j.optString("serviceName"),
        security = SecurityType.valueOf(j.optString("security", "NONE")),
        sni = j.optString("sni"),
        fingerprint = j.optString("fingerprint", "chrome"),
        publicKey = j.optString("publicKey"),
        shortId = j.optString("shortId"),
        spiderX = j.optString("spiderX"),
        ssMethod = j.optString("ssMethod", "aes-256-gcm"),
        obfsPassword = j.optString("obfsPassword"),
        upMbps = j.optInt("upMbps", 0),
        downMbps = j.optInt("downMbps", 0),
        username = j.optString("username"),
        allowInsecure = j.optBoolean("allowInsecure", false),
        rawLink = j.optString("rawLink"),
        rawOutbound = j.optString("rawOutbound"),
        rawType = j.optString("rawType"),
        rawDependencies = j.optString("rawDependencies")
    )
}
