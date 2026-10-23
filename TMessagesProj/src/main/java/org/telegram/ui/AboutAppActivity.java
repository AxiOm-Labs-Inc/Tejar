package org.telegram.ui;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.graphics.Typeface;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;

import org.telegram.messenger.AndroidUtilities;
import org.telegram.messenger.ApplicationLoader;
import org.telegram.messenger.BetaUpdate;
import org.telegram.messenger.BuildConfig;
import org.telegram.messenger.LocaleController;
import org.telegram.messenger.NotificationCenter;
import org.telegram.messenger.R;
import org.telegram.messenger.browser.Browser;
import org.telegram.ui.ActionBar.ActionBar;
import org.telegram.ui.ActionBar.BaseFragment;
import org.telegram.ui.ActionBar.Theme;

public class AboutAppActivity extends BaseFragment implements NotificationCenter.NotificationCenterDelegate {

    private static final String RELEASES_URL = "https://github.com/AxiOm-Labs-Inc/Tejar/releases";

    private static final int COLOR_ACCENT = 0xFF6C5CE7;
    private static final int COLOR_ACCENT_BG = 0x1A6C5CE7;
    private static final int COLOR_GREEN = 0xFF4CAF50;
    private static final int COLOR_GREEN_BG = 0x1A4CAF50;

    private TextView checkResultText;
    private LinearLayout checkUpdateButton;
    private TextView checkUpdateButtonText;
    private ProgressBar checkProgress;
    private LinearLayout updateBlock;
    private TextView updateVersionText;
    private TextView updateChangelogText;
    private TextView updateButton;
    private LinearLayout downloadProgressRow;
    private ProgressBar downloadProgressBar;
    private TextView downloadProgressText;

    private boolean checking;

    private int dp(int v) {
        return AndroidUtilities.dp(v);
    }

    private GradientDrawable makeRoundRect(int radius, int color) {
        GradientDrawable drawable = new GradientDrawable();
        drawable.setCornerRadius(radius);
        drawable.setColor(color);
        return drawable;
    }

    private LinearLayout.LayoutParams marginParams(int bottom) {
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        params.bottomMargin = bottom;
        return params;
    }

    @Override
    public View createView(Context context) {
        actionBar.setBackButtonImage(R.drawable.ic_ab_back);
        actionBar.setTitle(LocaleController.getString(R.string.SettingsAboutApp));
        actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() {
            @Override
            public void onItemClick(int id) {
                if (id == -1) {
                    finishFragment();
                }
            }
        });

        ScrollView scrollView = new ScrollView(context);
        scrollView.setVerticalScrollBarEnabled(false);

        LinearLayout root = new LinearLayout(context);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(16), dp(24), dp(16), dp(24));
        scrollView.addView(root, new ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        // ── Шапка: иконка приложения, имя, версия-чип ──
        ImageView appIcon = new ImageView(context);
        try {
            Drawable icon = context.getPackageManager().getApplicationIcon(context.getPackageName());
            appIcon.setImageDrawable(icon);
        } catch (Exception ignore) {
        }
        LinearLayout.LayoutParams iconParams = new LinearLayout.LayoutParams(dp(84), dp(84));
        iconParams.gravity = Gravity.CENTER_HORIZONTAL;
        iconParams.bottomMargin = dp(12);
        root.addView(appIcon, iconParams);

        TextView appName = new TextView(context);
        appName.setText(context.getResources().getString(R.string.AppName));
        appName.setTextSize(24);
        appName.setTypeface(AndroidUtilities.bold());
        appName.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
        appName.setGravity(Gravity.CENTER_HORIZONTAL);
        root.addView(appName, marginParams(dp(8)));

        TextView versionChip = new TextView(context);
        versionChip.setText(getVersionString());
        versionChip.setTextSize(13);
        versionChip.setTypeface(Typeface.DEFAULT_BOLD);
        versionChip.setTextColor(COLOR_ACCENT);
        versionChip.setBackground(makeRoundRect(dp(20), COLOR_ACCENT_BG));
        versionChip.setPadding(dp(14), dp(6), dp(14), dp(6));
        LinearLayout.LayoutParams chipParams = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        chipParams.gravity = Gravity.CENTER_HORIZONTAL;
        chipParams.bottomMargin = dp(6);
        root.addView(versionChip, chipParams);

        TextView baseVersionText = new TextView(context);
        baseVersionText.setText(LocaleController.formatString("SettingsBasedOnTelegram", R.string.SettingsBasedOnTelegram, BuildConfig.TELEGRAM_BASE_VERSION));
        baseVersionText.setTextSize(12);
        baseVersionText.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText));
        baseVersionText.setGravity(Gravity.CENTER_HORIZONTAL);
        LinearLayout.LayoutParams baseVersionParams = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        baseVersionParams.gravity = Gravity.CENTER_HORIZONTAL;
        baseVersionParams.bottomMargin = dp(24);
        root.addView(baseVersionText, baseVersionParams);

        // ── Карточка: GitHub Releases ──
        LinearLayout githubCard = new LinearLayout(context);
        githubCard.setOrientation(LinearLayout.HORIZONTAL);
        githubCard.setGravity(Gravity.CENTER_VERTICAL);
        githubCard.setBackground(makeRoundRect(dp(16), Theme.getColor(Theme.key_windowBackgroundGray)));
        githubCard.setPadding(dp(16), dp(14), dp(16), dp(14));
        githubCard.setOnClickListener(v -> Browser.openUrl(getParentActivity(), RELEASES_URL));
        root.addView(githubCard, marginParams(dp(12)));

        TextView githubIcon = new TextView(context);
        githubIcon.setText("↗");
        githubIcon.setTextSize(16);
        githubIcon.setTypeface(Typeface.DEFAULT_BOLD);
        githubIcon.setTextColor(COLOR_ACCENT);
        githubIcon.setGravity(Gravity.CENTER);
        LinearLayout.LayoutParams ghIconParams = new LinearLayout.LayoutParams(dp(32), dp(32));
        ghIconParams.rightMargin = dp(12);
        githubIcon.setBackground(makeRoundRect(dp(16), COLOR_ACCENT_BG));
        githubCard.addView(githubIcon, ghIconParams);

        LinearLayout githubTextBlock = new LinearLayout(context);
        githubTextBlock.setOrientation(LinearLayout.VERTICAL);
        githubCard.addView(githubTextBlock, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        TextView githubTitle = new TextView(context);
        githubTitle.setText(LocaleController.getString(R.string.SettingsGithubReleases));
        githubTitle.setTextSize(15);
        githubTitle.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
        githubTextBlock.addView(githubTitle);

        TextView githubSub = new TextView(context);
        githubSub.setText("github.com/AxiOm-Labs-Inc/Tejar");
        githubSub.setTextSize(12);
        githubSub.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText));
        githubTextBlock.addView(githubSub);

        TextView chevron = new TextView(context);
        chevron.setText("›");
        chevron.setTextSize(22);
        chevron.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText));
        githubCard.addView(chevron);

        if (ApplicationLoader.applicationLoaderInstance != null && ApplicationLoader.applicationLoaderInstance.isCustomUpdate()) {
            // ── Кнопка «Проверить обновление» ──
            checkUpdateButton = new LinearLayout(context);
            checkUpdateButton.setOrientation(LinearLayout.HORIZONTAL);
            checkUpdateButton.setGravity(Gravity.CENTER);
            checkUpdateButton.setBackground(makeRoundRect(dp(16), COLOR_ACCENT));
            checkUpdateButton.setPadding(dp(16), dp(14), dp(16), dp(14));
            checkUpdateButton.setOnClickListener(v -> doCheckForUpdate());
            root.addView(checkUpdateButton, marginParams(dp(8)));

            checkProgress = new ProgressBar(context);
            checkProgress.setVisibility(View.GONE);
            LinearLayout.LayoutParams progressParams = new LinearLayout.LayoutParams(dp(18), dp(18));
            progressParams.rightMargin = dp(10);
            checkUpdateButton.addView(checkProgress, progressParams);

            checkUpdateButtonText = new TextView(context);
            checkUpdateButtonText.setText(LocaleController.getString(R.string.SettingsCheckForUpdate));
            checkUpdateButtonText.setTextSize(15);
            checkUpdateButtonText.setTypeface(Typeface.DEFAULT_BOLD);
            checkUpdateButtonText.setTextColor(0xFFFFFFFF);
            checkUpdateButton.addView(checkUpdateButtonText, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT));

            checkResultText = new TextView(context);
            checkResultText.setTextSize(13);
            checkResultText.setTextColor(COLOR_GREEN);
            checkResultText.setGravity(Gravity.CENTER_HORIZONTAL);
            checkResultText.setVisibility(View.GONE);
            checkResultText.setBackground(makeRoundRect(dp(12), COLOR_GREEN_BG));
            checkResultText.setPadding(dp(14), dp(8), dp(14), dp(8));
            root.addView(checkResultText, marginParams(dp(12)));

            // ── Карточка найденного обновления ──
            updateBlock = new LinearLayout(context);
            updateBlock.setOrientation(LinearLayout.VERTICAL);
            updateBlock.setVisibility(View.GONE);
            updateBlock.setBackground(makeRoundRect(dp(16), COLOR_ACCENT_BG));
            updateBlock.setPadding(dp(18), dp(16), dp(18), dp(16));
            LinearLayout.LayoutParams updateParams = marginParams(0);
            updateParams.topMargin = dp(8);
            root.addView(updateBlock, updateParams);

            updateVersionText = new TextView(context);
            updateVersionText.setTextSize(16);
            updateVersionText.setTypeface(AndroidUtilities.bold());
            updateVersionText.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
            updateBlock.addView(updateVersionText);

            updateChangelogText = new TextView(context);
            updateChangelogText.setTextSize(14);
            updateChangelogText.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText));
            updateChangelogText.setPadding(0, dp(6), 0, dp(14));
            updateBlock.addView(updateChangelogText);

            downloadProgressRow = new LinearLayout(context);
            downloadProgressRow.setOrientation(LinearLayout.VERTICAL);
            downloadProgressRow.setVisibility(View.GONE);
            downloadProgressRow.setPadding(0, 0, 0, dp(14));
            updateBlock.addView(downloadProgressRow, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

            downloadProgressBar = new ProgressBar(context, null, android.R.attr.progressBarStyleHorizontal);
            downloadProgressBar.setMax(100);
            downloadProgressBar.getProgressDrawable().setColorFilter(COLOR_ACCENT, android.graphics.PorterDuff.Mode.SRC_IN);
            LinearLayout.LayoutParams barParams = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(6));
            barParams.bottomMargin = dp(6);
            downloadProgressRow.addView(downloadProgressBar, barParams);

            downloadProgressText = new TextView(context);
            downloadProgressText.setTextSize(13);
            downloadProgressText.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText));
            downloadProgressRow.addView(downloadProgressText, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT));

            updateButton = new TextView(context);
            updateButton.setText(LocaleController.getString(R.string.SettingsUpdateNow));
            updateButton.setTextSize(15);
            updateButton.setTypeface(Typeface.DEFAULT_BOLD);
            updateButton.setTextColor(0xFFFFFFFF);
            updateButton.setGravity(Gravity.CENTER);
            updateButton.setBackground(makeRoundRect(dp(12), COLOR_ACCENT));
            updateButton.setPadding(0, dp(12), 0, dp(12));
            updateButton.setOnClickListener(v -> {
                BetaUpdate update = ApplicationLoader.applicationLoaderInstance.getUpdate();
                if (update != null && getParentActivity() != null) {
                    ApplicationLoader.applicationLoaderInstance.showCustomUpdateAppPopup(getParentActivity(), update, currentAccount);
                }
            });
            updateBlock.addView(updateButton, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

            refreshUpdateBlock(false);
        }

        fragmentView = scrollView;
        fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
        return fragmentView;
    }

    private String getVersionString() {
        try {
            PackageInfo pInfo = ApplicationLoader.applicationContext.getPackageManager()
                    .getPackageInfo(ApplicationLoader.applicationContext.getPackageName(), 0);
            return LocaleController.formatString("SettingsAppVersion", R.string.SettingsAppVersion, pInfo.versionName, pInfo.versionCode / 10);
        } catch (Exception e) {
            return "";
        }
    }

    private void doCheckForUpdate() {
        if (checking || ApplicationLoader.applicationLoaderInstance == null) {
            return;
        }
        checking = true;
        checkUpdateButton.setEnabled(false);
        checkUpdateButton.setAlpha(0.7f);
        checkProgress.setVisibility(View.VISIBLE);
        checkResultText.setVisibility(View.GONE);
        ApplicationLoader.applicationLoaderInstance.checkUpdate(true, () -> AndroidUtilities.runOnUIThread(() -> {
            checking = false;
            if (checkUpdateButton == null) {
                return;
            }
            checkUpdateButton.setEnabled(true);
            checkUpdateButton.setAlpha(1f);
            checkProgress.setVisibility(View.GONE);
            refreshUpdateBlock(true);
        }));
    }

    private void refreshUpdateBlock(boolean afterManualCheck) {
        if (ApplicationLoader.applicationLoaderInstance == null || updateBlock == null) {
            return;
        }
        BetaUpdate update = ApplicationLoader.applicationLoaderInstance.getUpdate();
        if (update != null) {
            updateBlock.setVisibility(View.VISIBLE);
            updateVersionText.setText(LocaleController.formatString("SettingsUpdateVersionAvailable", R.string.SettingsUpdateVersionAvailable, update.version));
            updateChangelogText.setText(update.changelog != null ? update.changelog : "");
            updateChangelogText.setVisibility(update.changelog != null && !update.changelog.isEmpty() ? View.VISIBLE : View.GONE);
            if (checkResultText != null) {
                checkResultText.setVisibility(View.GONE);
            }

            boolean downloading = ApplicationLoader.applicationLoaderInstance.isDownloadingUpdate();
            downloadProgressRow.setVisibility(downloading ? View.VISIBLE : View.GONE);
            updateButton.setVisibility(downloading ? View.GONE : View.VISIBLE);
            if (downloading) {
                int percent = (int) (ApplicationLoader.applicationLoaderInstance.getDownloadingUpdateProgress() * 100);
                downloadProgressBar.setProgress(percent);
                downloadProgressText.setText(LocaleController.formatString("SettingsUpdateDownloading", R.string.SettingsUpdateDownloading, percent));
            }
        } else {
            updateBlock.setVisibility(View.GONE);
            if (afterManualCheck && checkResultText != null) {
                checkResultText.setText(LocaleController.getString(R.string.SettingsUpToDate));
                checkResultText.setVisibility(View.VISIBLE);
            }
        }
    }

    @Override
    public void onResume() {
        super.onResume();
        refreshUpdateBlock(false);
    }

    @Override
    public void didReceivedNotification(int id, int account, Object... args) {
        if (id == NotificationCenter.appUpdateAvailable || id == NotificationCenter.appUpdateLoading) {
            refreshUpdateBlock(false);
        }
    }

    @Override
    public boolean onFragmentCreate() {
        NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.appUpdateAvailable);
        NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.appUpdateLoading);
        return super.onFragmentCreate();
    }

    @Override
    public void onFragmentDestroy() {
        NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.appUpdateAvailable);
        NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.appUpdateLoading);
        super.onFragmentDestroy();
    }
}
