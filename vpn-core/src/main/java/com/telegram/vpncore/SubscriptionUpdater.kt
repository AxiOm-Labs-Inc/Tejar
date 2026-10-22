package com.telegram.vpncore

import android.content.Context
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.util.concurrent.ConcurrentHashMap

/**
 * Refreshes subscriptions, both on demand (the settings screen) and automatically.
 *
 * One code path serves both, so a manual and a background refresh cannot disagree about what
 * "updated" means. Never logs the subscription URL: it carries a per-user panel token.
 */
object SubscriptionUpdater {

    private const val TAG = "SubscriptionUpdater"

    /** Panels rarely change faster than this; polling more often only costs battery and traffic. */
    const val REFRESH_INTERVAL_MS = VpnSubscription.DEFAULT_REFRESH_MS

    /** After a failed automatic refresh, leave the subscription alone for this long. */
    const val FAILURE_BACKOFF_MS = 15L * 60 * 1000

    /**
     * Outcome of [refresh]. [changed] is false when the panel returned the same servers;
     * [skipped] lists the entries left out (unsupported, invalid, refused by the core).
     */
    sealed class Result {
        data class Success(
            val fetched: List<VpnConfig>,
            val changed: Boolean,
            val skipped: List<SkippedEntry> = emptyList()
        ) : Result()
        data class Failure(val message: String) : Result()
    }

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    // One lock for all subscriptions: refreshes are rare and short, and a single lock also
    // keeps the config repository's read-modify-write saves from interleaving.
    private val mutex = Mutex()

    // subscription id -> time of the last failed automatic attempt (in-memory: a restart may retry).
    private val lastFailure = ConcurrentHashMap<String, Long>()

    private val _lastRefresh = MutableStateFlow(0L)

    /** Bumped after every successful refresh so an open screen can reload its lists. */
    val lastRefresh: StateFlow<Long> = _lastRefresh

    /**
     * Whether [a] and [b] describe the same servers in the same order, ignoring [VpnConfig.id].
     * Link-based subscriptions get random ids on every fetch, so comparing ids would report a
     * change (and restart the tunnel) on every refresh.
     */
    fun sameServers(a: List<VpnConfig>, b: List<VpnConfig>): Boolean =
        a.size == b.size && a.indices.all { a[it].copy(id = "") == b[it].copy(id = "") }

    /** Manual or automatic refresh of [sub]; ignores the interval and the failure backoff. */
    suspend fun refresh(context: Context, sub: VpnSubscription): Result =
        mutex.withLock { refreshLocked(context, sub) }

    private suspend fun refreshLocked(context: Context, sub: VpnSubscription): Result {
        val appContext = context.applicationContext
        val configRepo = VpnConfigRepository(appContext)
        val subRepo = VpnSubscriptionRepository(appContext)
        try {
            val parsed = SubscriptionFetcher.fetch(sub.url)
            // One server the core cannot load would take every other one down with it at
            // start, so ask the core about each before it reaches the stored list.
            val validation = VpnProxyManager.getInstance(appContext).serverValidator().filter(parsed.servers)
            val fetched = validation.valid
            val skipped = parsed.skipped + validation.rejected
            // An empty answer is a broken panel, not "no servers": keep what we have.
            if (fetched.isEmpty()) {
                return Result.Failure(
                    if (skipped.isEmpty()) "No servers found in subscription"
                    else "No usable servers (skipped ${skipped.size}: ${ParseResult.describe(skipped)})"
                )
            }

            val oldSub = (subRepo.getById(sub.id) ?: sub).withInfo(parsed.info)
            val stored = configRepo.getAll().associateBy { it.id }
            val oldConfigs = oldSub.configIds.mapNotNull { stored[it] }
            val now = System.currentTimeMillis()

            if (sameServers(oldConfigs, fetched)) {
                subRepo.save(oldSub.copy(lastUpdated = now))
                lastFailure.remove(sub.id)
                _lastRefresh.value = now
                return Result.Success(fetched, changed = false, skipped = skipped)
            }

            val activeBefore = configRepo.getActive()
            val pinnedBefore = configRepo.getPinnedId()
            oldSub.configIds.forEach { configRepo.delete(it) }
            fetched.forEach { configRepo.save(it) }
            subRepo.save(oldSub.copy(lastUpdated = now, configIds = fetched.map { it.id }))

            val newIds = fetched.map { it.id }.toSet()
            // Deleting the active config already cleared it; give the tunnel a server from the
            // new list instead of leaving it with none.
            if (activeBefore != null && activeBefore.id in oldSub.configIds &&
                activeBefore.id !in newIds
            ) {
                configRepo.setActive(fetched.first().id)
            }
            if (pinnedBefore != null && pinnedBefore in oldSub.configIds &&
                pinnedBefore !in newIds
            ) {
                configRepo.setPinnedId(null)
            }

            VpnProxyManager.getInstance(appContext).reloadServers()
            lastFailure.remove(sub.id)
            _lastRefresh.value = now
            return Result.Success(fetched, changed = true, skipped = skipped)
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Exception) {
            // Some fetch errors quote the URL; scrub it before the message reaches a log or toast.
            val message = (e.message ?: e.javaClass.simpleName).replace(sub.url, "<url>")
            return Result.Failure(message)
        }
    }

    /** Refreshes every subscription older than [REFRESH_INTERVAL_MS] in the background. */
    fun refreshStaleAsync(context: Context) {
        val appContext = context.applicationContext
        scope.launch {
            val subs = runCatching { VpnSubscriptionRepository(appContext).getAll() }
                .getOrDefault(emptyList())
            val now = System.currentTimeMillis()
            for (sub in subs) {
                if (now - sub.lastUpdated < sub.refreshIntervalMs()) continue
                val failedAt = lastFailure[sub.id]
                if (failedAt != null && now - failedAt < FAILURE_BACKOFF_MS) continue
                when (val result = refresh(appContext, sub)) {
                    is Result.Success -> Log.d(TAG, "Refreshed \"${sub.name}\", changed=${result.changed}")
                    is Result.Failure -> {
                        lastFailure[sub.id] = System.currentTimeMillis()
                        Log.w(TAG, "Auto-refresh of \"${sub.name}\" failed: ${result.message}")
                    }
                }
            }
        }
    }
}
