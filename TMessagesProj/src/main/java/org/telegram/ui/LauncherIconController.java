package org.telegram.ui;

import android.content.ComponentName;
import android.content.Context;
import android.content.pm.PackageManager;

import org.telegram.messenger.ApplicationLoader;
import org.telegram.messenger.R;

public class LauncherIconController {
    public static void tryFixLauncherIconIfNeeded() {
        for (LauncherIcon icon : LauncherIcon.values()) {
            if (isEnabled(icon)) {
                return;
            }
        }

        setIcon(LauncherIcon.DEFAULT);
    }

    public static boolean isEnabled(LauncherIcon icon) {
        Context ctx = ApplicationLoader.applicationContext;
        int i = ctx.getPackageManager().getComponentEnabledSetting(icon.getComponentName(ctx));
        return i == PackageManager.COMPONENT_ENABLED_STATE_ENABLED || i == PackageManager.COMPONENT_ENABLED_STATE_DEFAULT && icon == LauncherIcon.DEFAULT;
    }

    public static void setIcon(LauncherIcon icon) {
        Context ctx = ApplicationLoader.applicationContext;
        PackageManager pm = ctx.getPackageManager();
        for (LauncherIcon i : LauncherIcon.values()) {
            pm.setComponentEnabledSetting(i.getComponentName(ctx), i == icon ? PackageManager.COMPONENT_ENABLED_STATE_ENABLED :
                    PackageManager.COMPONENT_ENABLED_STATE_DISABLED, PackageManager.DONT_KILL_APP);
        }
    }

    public enum LauncherIcon {
        DEFAULT("DefaultIcon", R.mipmap.tejar_icon_background, R.mipmap.tejar_icon_foreground, R.string.AppIconDefault),
        VINTAGE("VintageIcon", R.mipmap.tejar_icon_vintage_background, R.mipmap.tejar_icon_vintage_foreground, R.string.AppIconVintage),
        AQUA("AquaIcon", R.mipmap.tejar_icon_aqua_background, R.mipmap.tejar_icon_aqua_foreground, R.string.AppIconAqua),
        PREMIUM("PremiumIcon", R.mipmap.tejar_icon_premium_background, R.mipmap.tejar_icon_premium_foreground, R.string.AppIconPremium, true),
        TURBO("TurboIcon", R.mipmap.tejar_icon_turbo_background, R.mipmap.tejar_icon_turbo_foreground, R.string.AppIconTurbo, true),
        NOX("NoxIcon", R.mipmap.tejar_icon_nox_background, R.mipmap.tejar_icon_nox_foreground, R.string.AppIconNox, true);

        public final String key;
        public final int background;
        public final int foreground;
        public final int title;
        public final boolean premium;

        private ComponentName componentName;

        public ComponentName getComponentName(Context ctx) {
            if (componentName == null) {
                componentName = new ComponentName(ctx.getPackageName(), "org.telegram.messenger." + key);
            }
            return componentName;
        }

        LauncherIcon(String key, int background, int foreground, int title) {
            this(key, background, foreground, title, false);
        }

        LauncherIcon(String key, int background, int foreground, int title, boolean premium) {
            this.key = key;
            this.background = background;
            this.foreground = foreground;
            this.title = title;
            this.premium = premium;
        }
    }
}
