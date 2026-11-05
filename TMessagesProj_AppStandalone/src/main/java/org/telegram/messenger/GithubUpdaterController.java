package org.telegram.messenger;

import android.app.Activity;
import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.content.pm.SigningInfo;
import android.os.Build;
import android.text.TextUtils;

import org.json.JSONArray;
import org.json.JSONObject;
import org.telegram.ui.web.HttpGetFileTask;
import org.telegram.ui.web.HttpGetTask;

import java.io.File;
import java.security.MessageDigest;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Checks AxiOm-Labs-Inc/Tejar GitHub Releases for a newer build and downloads it.
 * Modeled on BetaUpdaterController (HockeyApp flavor), reusing the same BetaUpdate
 * model and UpdateAppAlertDialog/UpdateLayout UI — only the update source differs.
 *
 * Unlike BetaUpdaterController's private App Center feed, this reads a public GitHub
 * API endpoint, so the downloaded APK's signing certificate is verified against the
 * currently installed app before it's offered for install (see verifySignature()) —
 * this is what stands in for TLS pinning against a compromised/MITM'd release asset.
 */
public class GithubUpdaterController {

    private static final String RELEASES_URL = "https://api.github.com/repos/AxiOm-Labs-Inc/Tejar/releases/latest";
    // Beta channel: /releases/latest skips pre-releases, so the list is scanned instead.
    private static final String RELEASES_LIST_URL = "https://api.github.com/repos/AxiOm-Labs-Inc/Tejar/releases?per_page=20";
    /** Set from the About screen (AboutAppActivity) in the same "github_update" preferences. */
    private static final String KEY_BETA_CHANNEL = "beta_channel";
    // Tejar-<versionName>-<versionCode>-<arm64|armv7>-standalone.apk
    // A release carries one asset per ABI; pickAbiTag() selects the one this device can install.
    private static final Pattern ASSET_NAME_PATTERN = Pattern.compile(
        "^Tejar-(.+)-(\\d+)-(arm64|armv7)-standalone\\.apk$"
    );

    /**
     * ABI tag of the release asset this device can run: "arm64" on 64-bit ARM,
     * "armv7" otherwise. A 64-bit device running the 32-bit build still reports
     * arm64-v8a here, so it migrates to the arm64 asset on the next update.
     */
    private static String pickAbiTag() {
        final String[] abis = Build.SUPPORTED_ABIS;
        if (abis != null) {
            for (String abi : abis) {
                if ("arm64-v8a".equals(abi)) return "arm64";
            }
        }
        return "armv7";
    }

    private static GithubUpdaterController instance;
    public static GithubUpdaterController getInstance() {
        if (instance == null) {
            instance = new GithubUpdaterController();
        }
        return instance;
    }

    private String version;
    private int versionCode;
    private String changelog;
    private String apkUrl;
    private String path;
    private long lastCheck;

    public GithubUpdaterController() {
        load();
    }

    private SharedPreferences getSharedPreferences() {
        return ApplicationLoader.applicationContext.getSharedPreferences("github_update", Activity.MODE_PRIVATE);
    }

    private void load() {
        final SharedPreferences prefs = getSharedPreferences();
        version = prefs.getString("version", null);
        versionCode = prefs.getInt("versionCode", 0);
        changelog = prefs.getString("changelog", null);
        apkUrl = prefs.getString("apkUrl", null);
        path = prefs.getString("path", null);
        lastCheck = prefs.getLong("lastCheck", 0L);

        if (getCurrentVersionCode() >= versionCode || (!TextUtils.isEmpty(path) && !new File(path).exists())) {
            version = null;
            versionCode = 0;
            changelog = null;
            apkUrl = null;
            path = null;
            save();
        }
    }

    private void save() {
        final SharedPreferences.Editor e = getSharedPreferences().edit();
        if (TextUtils.isEmpty(version)) e.remove("version"); else e.putString("version", version);
        if (TextUtils.isEmpty(changelog)) e.remove("changelog"); else e.putString("changelog", changelog);
        if (TextUtils.isEmpty(apkUrl)) e.remove("apkUrl"); else e.putString("apkUrl", apkUrl);
        if (versionCode == 0) e.remove("versionCode"); else e.putInt("versionCode", versionCode);
        if (TextUtils.isEmpty(path)) e.remove("path"); else e.putString("path", path);
        if (lastCheck == 0) e.remove("lastCheck"); else e.putLong("lastCheck", lastCheck);
        e.apply();
    }

    private static final long CHECK_INTERVAL_PAUSED = 1000L * 60 * 60 * 24; // 1 day
    private static final long CHECK_INTERVAL = 1000L * 60 * 60 * 6; // 6 hours

    private boolean firstCheck = true;
    private boolean checkingForUpdate;

    public void checkForUpdate(boolean force, Runnable whenDone) {
        if (checkingForUpdate) {
            if (whenDone != null) whenDone.run();
            return;
        }
        if (firstCheck) {
            force = true;
        }
        if (!force && System.currentTimeMillis() - lastCheck < (ApplicationLoader.mainInterfacePaused ? CHECK_INTERVAL_PAUSED : CHECK_INTERVAL)) {
            if (whenDone != null) whenDone.run();
            return;
        }

        checkingForUpdate = true;
        firstCheck = false;
        final boolean beta = getSharedPreferences().getBoolean(KEY_BETA_CHANNEL, false);
        final String url = beta ? RELEASES_LIST_URL : RELEASES_URL;
        new HttpGetTask(str -> AndroidUtilities.runOnUIThread(() -> {
            checkingForUpdate = false;
            lastCheck = System.currentTimeMillis();
            try {
                if (str == null) throw new Exception("empty response");
                final String abiTag = pickAbiTag();
                // Beta: the release with the highest versionCode for this ABI, pre-releases included.
                ReleaseApk best = null;
                if (beta) {
                    final JSONArray releases = new JSONArray(str);
                    for (int i = 0; i < releases.length(); i++) {
                        final JSONObject release = releases.getJSONObject(i);
                        if (release.optBoolean("draft", false)) continue;
                        final ReleaseApk apk = findApk(release, abiTag);
                        if (apk != null && (best == null || apk.versionCode > best.versionCode)) {
                            best = apk;
                        }
                    }
                } else {
                    best = findApk(new JSONObject(str), abiTag);
                }
                final String newVersion = best != null ? best.version : null;
                final int newVersionCode = best != null ? best.versionCode : 0;
                final String newApkUrl = best != null ? best.url : null;
                final String newChangelog = best != null ? best.changelog : null;

                if (newApkUrl != null && newApkUrl.startsWith("https://") && newVersionCode > getCurrentVersionCode()) {
                    if (newVersionCode != versionCode) {
                        // a genuinely new release: drop any previously downloaded (now stale) apk
                        if (!TextUtils.isEmpty(path)) {
                            try { new File(path).delete(); } catch (Exception ignore) {}
                        }
                        path = null;
                    }
                    version = newVersion;
                    versionCode = newVersionCode;
                    apkUrl = newApkUrl;
                    changelog = newChangelog;
                } else {
                    if (!TextUtils.isEmpty(path)) {
                        try { new File(path).delete(); } catch (Exception ignore) {}
                    }
                    version = null;
                    versionCode = 0;
                    apkUrl = null;
                    changelog = null;
                    path = null;
                }
                save();
            } catch (Exception e) {
                FileLog.e("GithubUpdaterController: failed to check " + url, e);
            }
            if (whenDone != null) whenDone.run();
        }))
            .setHeader("Accept", "application/vnd.github+json")
            .setHeader("User-Agent", "Tejar-Android/" + getCurrentVersionName())
            .execute(url);
    }

    private static final class ReleaseApk {
        String version;
        int versionCode;
        String url;
        String changelog;
    }

    /** The APK asset of [release] for [abiTag], or null if the release has none. */
    private static ReleaseApk findApk(JSONObject release, String abiTag) throws Exception {
        final JSONArray assets = release.getJSONArray("assets");
        for (int i = 0; i < assets.length(); i++) {
            final JSONObject asset = assets.getJSONObject(i);
            final Matcher m = ASSET_NAME_PATTERN.matcher(asset.optString("name", ""));
            if (m.matches() && abiTag.equals(m.group(3))) {
                final ReleaseApk apk = new ReleaseApk();
                apk.version = m.group(1);
                apk.versionCode = Integer.parseInt(m.group(2));
                apk.url = asset.optString("browser_download_url", null);
                apk.changelog = release.optString("body", null);
                return apk;
            }
        }
        return null;
    }

    /** True while a discovered release hasn't been announced to the user yet. */
    public boolean shouldNotifyAboutUpdate() {
        if (version == null || versionCode == 0) return false;
        return getSharedPreferences().getInt("notifiedVersionCode", 0) != versionCode;
    }

    public void setUpdateNotified() {
        getSharedPreferences().edit().putInt("notifiedVersionCode", versionCode).apply();
    }

    public BetaUpdate getUpdate() {
        if (version == null || versionCode == 0) return null;
        return new BetaUpdate(version, versionCode, changelog);
    }

    private boolean downloading;
    private float downloadingProgress;
    private int lastNotifiedPercent = -1;
    private HttpGetFileTask downloadingTask;

    public void downloadUpdate() {
        if (downloading || !TextUtils.isEmpty(path) || TextUtils.isEmpty(apkUrl)) return;
        if (!apkUrl.startsWith("https://")) {
            FileLog.e("GithubUpdaterController: refusing non-HTTPS apk url");
            return;
        }

        downloading = true;
        downloadingProgress = 0.0f;
        lastNotifiedPercent = -1;
        // Keeps the process alive and exempt from Doze/battery-saver network throttling
        // while the AsyncTask below runs, so the download survives backgrounding.
        UpdateDownloadService.start(ApplicationLoader.applicationContext);
        NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.appUpdateLoading);

        downloadingTask = new HttpGetFileTask(
            downloadedFile -> AndroidUtilities.runOnUIThread(() -> {
                if (downloadedFile != null && verifySignature(downloadedFile)) {
                    path = downloadedFile.getAbsolutePath();
                    save();
                } else if (downloadedFile != null) {
                    FileLog.e("GithubUpdaterController: downloaded apk signature mismatch, discarding");
                    try { downloadedFile.delete(); } catch (Exception ignore) {}
                    version = null;
                    versionCode = 0;
                    apkUrl = null;
                    changelog = null;
                    path = null;
                    save();
                } else {
                    // Download failed (network dropped) or was cancelled — that says nothing about
                    // the release itself, so keep the discovered update and let the user retry.
                    // Wiping it here would make a flaky connection look like "no update available".
                    FileLog.e("GithubUpdaterController: update download did not complete, keeping update info for retry");
                }
                downloading = false;
                downloadingProgress = 1.0f;
                NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.appUpdateAvailable);
            }),
            progress -> {
                downloadingProgress = progress;
                // HttpGetFileTask reports every 16 KB read, i.e. thousands of times for a ~140 MB
                // apk. Only wake observers when the visible percentage actually moves, otherwise
                // the UI thread and the notification manager get flooded (and rate-limited).
                final int percent = (int) (progress * 100);
                if (percent != lastNotifiedPercent) {
                    lastNotifiedPercent = percent;
                    NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.appUpdateLoading);
                }
            }
        ).setOverrideExtension("apk");
        downloadingTask.execute(apkUrl);
    }

    public void cancelDownloadingUpdate() {
        if (!downloading) return;
        if (downloadingTask != null) downloadingTask.cancel(false);
        downloading = false;
        NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.appUpdateAvailable);
    }

    public boolean isDownloading() {
        return downloading;
    }

    public float getDownloadingProgress() {
        return downloadingProgress;
    }

    public File getDownloadedFile() {
        if (path == null) return null;
        final File file = new File(path);
        if (!file.exists()) {
            path = null;
            save();
            return null;
        }
        return file;
    }

    /**
     * Confirms the downloaded APK is signed with the same certificate as the running app,
     * i.e. it really is a Tejar build and not something injected via a compromised/MITM'd
     * GitHub asset. HTTPS alone doesn't buy us this — it only protects the connection to
     * whichever host actually served the bytes.
     */
    private boolean verifySignature(File apk) {
        try {
            // GET_SIGNING_CERTIFICATES only populates signingInfo on API 28+; below that the
            // legacy signatures[] array requires GET_SIGNATURES instead (with the wrong flag
            // both come back null and verification would always fail on Android < 9).
            @SuppressWarnings("deprecation")
            final int flags = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P
                ? PackageManager.GET_SIGNING_CERTIFICATES
                : PackageManager.GET_SIGNATURES;
            final PackageManager pm = ApplicationLoader.applicationContext.getPackageManager();
            final byte[] installedCert = getPrimarySigningCertHash(pm.getPackageInfo(
                ApplicationLoader.applicationContext.getPackageName(),
                flags
            ));
            final PackageInfo apkInfo = pm.getPackageArchiveInfo(apk.getAbsolutePath(), flags);
            if (apkInfo == null) return false;
            final byte[] apkCert = getPrimarySigningCertHash(apkInfo);
            return installedCert != null && apkCert != null && MessageDigest.isEqual(installedCert, apkCert);
        } catch (Exception e) {
            FileLog.e("GithubUpdaterController: signature verification failed", e);
            return false;
        }
    }

    private byte[] getPrimarySigningCertHash(PackageInfo info) throws Exception {
        Signature[] signatures = null;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            final SigningInfo signingInfo = info.signingInfo;
            if (signingInfo != null) {
                signatures = signingInfo.hasMultipleSigners()
                    ? signingInfo.getApkContentsSigners()
                    : signingInfo.getSigningCertificateHistory();
            }
        } else {
            //noinspection deprecation
            signatures = info.signatures;
        }
        if (signatures == null || signatures.length == 0) return null;
        final MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(signatures[0].toByteArray());
    }

    private String getCurrentVersionName() {
        try {
            return ApplicationLoader.applicationContext.getPackageManager()
                .getPackageInfo(ApplicationLoader.applicationContext.getPackageName(), 0).versionName;
        } catch (Exception e) {
            return "unknown";
        }
    }

    private int getCurrentVersionCode() {
        try {
            return ApplicationLoader.applicationContext.getPackageManager()
                .getPackageInfo(ApplicationLoader.applicationContext.getPackageName(), 0).versionCode;
        } catch (Exception e) {
            FileLog.e(e);
            return 0;
        }
    }
}
