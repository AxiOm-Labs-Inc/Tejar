#!/usr/bin/env python3
"""Generates every Tejar app icon from the vector source in this folder.

    pip install cairosvg pillow
    python3 branding/make_icons.py        # run from the repository root

Design: AxiOm's dark globe background and Omega, framed by a speech bubble (Tejar is the
messenger of the AxiOm family). The background is the AxiOm client's #1a1d3e -> #06070f radial
gradient; the mark is teal #5DCAA5, the client's "connected" colour, so Tejar and AxiOm (blue
#5BA3FF) never look alike on a home screen.

Outputs (overwritten):
  - adaptive icon layers (API 26+): mipmap-*/tejar_icon_{background,foreground,monochrome}.png
  - legacy icons (API 21-25): mipmap-*/ic_launcher{,_round}.png and the standalone ic_launcher_sa.png
  - conversation / call avatar: drawable-*/ic_launcher_dr.png
  - notification small icon (white silhouette): drawable-*/notification.png
  - branding/play-icon-512.png for the Google Play listing
  - alternative icons Vintage/Aqua/Premium/Turbo/Nox: mipmap-*/tejar_icon_<name>_{background,foreground}.png,
    the legacy icon_N_launcher{,_round,_sa}.png and their adaptive icon_N_launcher*.xml
"""
import io
import os

import cairosvg
from PIL import Image, ImageDraw

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES = os.path.join(ROOT, "TMessagesProj", "src", "main", "res")
RES_SA = os.path.join(ROOT, "TMessagesProj_AppStandalone", "src", "main", "res")

ACCENT = "#5DCAA5"  # AxiOm "connected" teal; AxiOm itself uses #5BA3FF

OMEGA = ("M265.03 333.65Q283.64 330.01 294.02 310.87Q304.4 291.73 304.8 260.18V242.11Q304.8 210.97 291.73 194.39"
         "Q278.65 177.81 255.87 177.81Q233.08 177.81 220.14 194.66Q207.2 211.51 207.2 242.38V257.62Q207.2 289.97 "
         "217.78 309.93Q228.36 329.88 247.91 333.65V355.49H181.58V334.33H211.38Q197.09 320.58 189 299.88Q180.91 "
         "279.19 180.91 257.35V242.38Q180.91 217.31 190.41 197.63Q199.92 177.94 217.04 167.22Q234.16 156.51 255.87 "
         "156.51Q277.44 156.51 294.49 167.02Q311.54 177.54 321.12 196.68Q330.69 215.83 331.09 240.09V257.62Q331.09 "
         "279.19 323 299.88Q314.91 320.58 300.62 334.33H330.28V355.49H265.03Z")

BUBBLE = ("M176,96 H336 A90,90 0 0 1 426,186 V326 A90,90 0 0 1 336,416 H196 L138,438 L140,404 "
          "A90,90 0 0 1 86,326 V186 A90,90 0 0 1 176,96 Z")

BACKGROUND = """<defs><radialGradient id="mbg" cx="30%" cy="25%" r="82%">
<stop offset="0%" stop-color="#1a1d3e"/><stop offset="80%" stop-color="#06070f"/></radialGradient></defs>
<rect width="512" height="512" fill="url(#mbg)"/>
<rect width="512" height="512" fill="#185FA5" fill-opacity="0.16"/>"""


def mark(color, stroke=5.5, globe_lines=True):
    """Bubble + globe meridians + Omega, in the 512 design space."""
    lines = ""
    if globe_lines:
        lines = (f'<g clip-path="url(#cl)"><ellipse cx="256" cy="256" rx="69.5" ry="170" fill="none" '
                 f'stroke="{color}" stroke-width="2" opacity="0.5"/><line x1="86" y1="256" x2="426" y2="256" '
                 f'stroke="{color}" stroke-width="2" opacity="0.35"/></g>')
    return (f'<clipPath id="cl"><path d="{BUBBLE}"/></clipPath>'
            f'<path d="{BUBBLE}" fill="none" stroke="{color}" stroke-width="{stroke}" stroke-linejoin="round"/>'
            f'{lines}<path d="{OMEGA}" fill="{color}"/>')


def svg(body, view="0 0 512 512"):
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{view}" width="512" height="512">'
            f'{body}</svg>')


# Adaptive icons: 108dp canvas, launcher masks show the central 72dp, the 66dp circle is safe.
# The mark (bubble bbox ~340x342 in the 512 space) is shrunk to ~50 % of the canvas and centred,
# so circle and squircle masks never cut the bubble.
def adaptive(body):
    s = 0.76
    dx, dy = 256 - 256 * s, 256 - 267 * s
    return f'<g transform="translate({dx:.1f},{dy:.1f}) scale({s})">{body}</g>'


def render(svg_text, size):
    png = cairosvg.svg2png(bytestring=svg_text.encode(), output_width=size, output_height=size)
    return Image.open(io.BytesIO(png)).convert("RGBA")


def save(img, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    img.save(path, optimize=True)


def masked(img, shape):
    m = Image.new("L", img.size, 0)
    d = ImageDraw.Draw(m)
    w = img.size[0]
    if shape == "circle":
        d.ellipse([0, 0, w - 1, w - 1], fill=255)
    else:
        d.rounded_rectangle([0, 0, w - 1, w - 1], radius=int(w * 0.22), fill=255)
    out = Image.new("RGBA", img.size, (0, 0, 0, 0))
    out.paste(img, (0, 0), m)
    return out


SVG_BG = svg(BACKGROUND)
SVG_FG = svg(adaptive(mark(ACCENT)))
SVG_MONO = svg(adaptive(mark("#FFFFFF", stroke=12, globe_lines=False)))
# full composite, cropped to the 72dp viewport of the 108dp adaptive canvas
SVG_FULL = svg(BACKGROUND + adaptive(mark(ACCENT)), view="85.3 85.3 341.3 341.3")
SVG_NOTIF = svg(mark("#FFFFFF", stroke=30, globe_lines=False), view="70 80 372 372")

DENSITIES = {"mdpi": 1, "hdpi": 1.5, "xhdpi": 2, "xxhdpi": 3, "xxxhdpi": 4}

for name, k in DENSITIES.items():
    mip = os.path.join(RES, f"mipmap-{name}")
    layer = round(108 * k)
    save(render(SVG_BG, layer), os.path.join(mip, "tejar_icon_background.png"))
    save(render(SVG_FG, layer), os.path.join(mip, "tejar_icon_foreground.png"))
    save(render(SVG_MONO, layer), os.path.join(mip, "tejar_icon_monochrome.png"))

    legacy = round(48 * k)
    full = render(SVG_FULL, legacy)
    save(masked(full, "squircle"), os.path.join(mip, "ic_launcher.png"))
    save(masked(full, "circle"), os.path.join(mip, "ic_launcher_round.png"))
    save(masked(full, "circle"), os.path.join(RES_SA, f"mipmap-{name}", "ic_launcher_sa.png"))
    save(masked(full, "circle"), os.path.join(RES, f"drawable-{name}", "ic_launcher_dr.png"))

    if name != "xxxhdpi":  # upstream ships notification.webp up to xxhdpi
        save(render(SVG_NOTIF, round(24 * k)), os.path.join(RES, f"drawable-{name}", "notification.png"))

# ── Alternative icons (Settings → Appearance → App icon) ──────────────────────────────────
# Same mark, recoloured. They keep Telegram's slots and names (icon_N_*), so Premium, Turbo and
# Nox stay Telegram Premium perks; only the artwork changes. N matches the manifest aliases.
def radial(a, b):
    return (f'<defs><radialGradient id="g" cx="30%" cy="25%" r="82%"><stop offset="0%" stop-color="{a}"/>'
            f'<stop offset="80%" stop-color="{b}"/></radialGradient></defs><rect width="512" height="512" fill="url(#g)"/>')


def linear(a, b):
    return (f'<defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="{a}"/>'
            f'<stop offset="100%" stop-color="{b}"/></linearGradient></defs><rect width="512" height="512" fill="url(#g)"/>')


VARIANTS = {  # name: (N, background, mark colour)
    "vintage": (6, radial("#6b4a32", "#2b1b10"), "#F3E2C0"),
    "aqua": (4, linear("#45D6E6", "#1873CC"), "#FFFFFF"),
    "premium": (3, linear("#6B93FF", "#E46ACE"), "#FFFFFF"),
    "turbo": (5, linear("#FFA63D", "#E3342F"), "#FFFFFF"),
    "nox": (2, radial("#2e3238", "#0a0b0d"), "#C9CED6"),
}

ADAPTIVE_XML = """<?xml version="1.0" encoding="utf-8"?>
<!-- Tejar {name} icon. Generated by branding/make_icons.py -->
<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android">
    <background android:drawable="@mipmap/tejar_icon_{name}_background" />
    <foreground android:drawable="@mipmap/tejar_icon_{name}_foreground" />
    <monochrome android:drawable="@mipmap/tejar_icon_monochrome" />
</adaptive-icon>
"""

for vname, (n, bg, color) in VARIANTS.items():
    v_bg = svg(bg)
    v_fg = svg(adaptive(mark(color)))
    v_full = svg(bg + adaptive(mark(color)), view="85.3 85.3 341.3 341.3")
    for name, k in DENSITIES.items():
        mip = os.path.join(RES, f"mipmap-{name}")
        layer = round(108 * k)
        save(render(v_bg, layer), os.path.join(mip, f"tejar_icon_{vname}_background.png"))
        save(render(v_fg, layer), os.path.join(mip, f"tejar_icon_{vname}_foreground.png"))
        full = render(v_full, round(48 * k))
        save(masked(full, "squircle"), os.path.join(mip, f"icon_{n}_launcher.png"))
        save(masked(full, "circle"), os.path.join(mip, f"icon_{n}_launcher_round.png"))
        save(masked(full, "circle"), os.path.join(RES_SA, f"mipmap-{name}", f"icon_{n}_launcher_sa.png"))
    for path in (os.path.join(RES, "mipmap-anydpi-v26", f"icon_{n}_launcher.xml"),
                 os.path.join(RES, "mipmap-anydpi-v26", f"icon_{n}_launcher_round.xml"),
                 os.path.join(RES_SA, "mipmap-anydpi-v26", f"icon_{n}_launcher_sa.xml")):
        with open(path, "w") as f:
            f.write(ADAPTIVE_XML.format(name=vname))

save(render(SVG_FULL, 512), os.path.join(ROOT, "branding", "play-icon-512.png"))
with open(os.path.join(ROOT, "branding", "tejar-icon.svg"), "w") as f:
    f.write(svg(BACKGROUND + mark(ACCENT)))
print("icons written")
