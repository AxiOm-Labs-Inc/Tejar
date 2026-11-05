package org.telegram.messenger;

import android.text.SpannableStringBuilder;
import android.text.Spanned;
import android.text.style.RelativeSizeSpan;

import androidx.annotation.Nullable;

import org.telegram.ui.Components.TypefaceSpan;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BetaUpdate {

    public final String version;
    public final int versionCode;

    @Nullable
    public final String changelog;

    public BetaUpdate(String version, int versionCode, String changelog) {
        this.version = version;
        this.versionCode = versionCode;
        this.changelog = changelog;
    }

    private static final Pattern BOLD = Pattern.compile("\\*\\*(.+?)\\*\\*");

    /**
     * The changelog (a GitHub release body) with the Markdown our release notes use rendered:
     * "#" headings, **bold** and "- " / "* " list items. Anything else is shown as written.
     */
    public CharSequence formattedChangelog() {
        if (changelog == null) return "";
        final SpannableStringBuilder out = new SpannableStringBuilder();
        final String[] lines = localizedChangelog().split("\n");
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            boolean heading = false;
            if (line.startsWith("#")) {
                line = line.replaceFirst("^#+\\s*", "");
                heading = true;
            } else if (line.startsWith("- ") || line.startsWith("* ")) {
                line = "• " + line.substring(2);
            }
            final int lineStart = out.length();
            final Matcher m = BOLD.matcher(line);
            int last = 0;
            while (m.find()) {
                out.append(line, last, m.start());
                final int boldStart = out.length();
                out.append(m.group(1));
                out.setSpan(new TypefaceSpan(AndroidUtilities.bold()), boldStart, out.length(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
                last = m.end();
            }
            out.append(line, last, line.length());
            if (heading && out.length() > lineStart) {
                out.setSpan(new TypefaceSpan(AndroidUtilities.bold()), lineStart, out.length(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
                out.setSpan(new RelativeSizeSpan(1.1f), lineStart, out.length(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
            }
            if (i < lines.length - 1) out.append('\n');
        }
        return out;
    }

    private static final Pattern ENGLISH_SECTION = Pattern.compile("\\n-{3,}\\s*\\n#+\\s*English\\s*\\n");

    /**
     * Release notes are written in Russian with an English copy after a "---" line and an
     * "# English" heading. Russian UIs get the part before it, every other language the English
     * part; notes without that section are shown whole.
     */
    private String localizedChangelog() {
        final String text = changelog.replace("\r", "").trim();
        final Matcher m = ENGLISH_SECTION.matcher(text);
        if (!m.find()) return text;
        final String language = LocaleController.getInstance().getCurrentLocale().getLanguage();
        return ("ru".equals(language) ? text.substring(0, m.start()) : text.substring(m.end())).trim();
    }

    public boolean higherThan(BetaUpdate update) {
        return update == null || SharedConfig.versionBiggerOrEqual(version, update.version) && versionCode > update.versionCode;
    }

}
