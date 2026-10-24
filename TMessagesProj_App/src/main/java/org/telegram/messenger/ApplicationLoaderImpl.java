package org.telegram.messenger;

import org.telegram.messenger.regular.BuildConfig;

/**
 * Google Play build of Tejar.
 *
 * Differences from the standalone (website) build:
 *  - no self-update: GithubUpdaterController lives only in TMessagesProj_AppStandalone,
 *    and LaunchActivity.checkAppUpdate() skips non-standalone builds, so updates
 *    come from Google Play only (Play policy forbids updating outside the store);
 *  - Telegram Premium / Stars purchases are hidden: a fork cannot sell them through
 *    Google Play Billing, and selling them by any other way inside a Play app
 *    breaks the Payments policy. Upstream provides IS_BILLING_UNAVAILABLE for this.
 */
public class ApplicationLoaderImpl extends ApplicationLoader {
    @Override
    public void onCreate() {
        BuildVars.IS_BILLING_UNAVAILABLE = true;
        super.onCreate();
    }

    @Override
    protected String onGetApplicationId() {
        return BuildConfig.APPLICATION_ID;
    }
}
