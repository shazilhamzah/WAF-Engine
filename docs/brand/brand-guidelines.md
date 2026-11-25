# WAF Studio — Brand & Logo Guidelines

## 1. The Logo
- **Idea**: **Glass-Box Shield** — a faceted shield split along its vertical axis into a solid left armour plate (reverse-proxy protection) and three horizontal inspection strata on the right (*Decode → Match → Score*), turning the traditional "black-box" security shield into an explainable glass box.
- **Versions**:
  - **Horizontal lockup** (primary): `waf-studio-horizontal-color.svg` · `waf-studio-horizontal-on-dark.svg`
  - **Stacked lockup** (vertical/square): `waf-studio-stacked-color.svg`
  - **Symbol-only**: `waf-studio-symbol-color.svg` · `waf-studio-symbol-on-dark.svg` · `waf-studio-symbol-small.svg` (dedicated 16–24 px cut)
  - **Wordmark-only**: `waf-studio-wordmark-color.svg`
  - **Single-colour & web-icon variants**: `variants/waf-studio-*-black.svg`, `*-white.svg`, `*-mono-0060c7.svg`, `favicon.svg`, `favicon.ico`, `apple-touch-icon.png`, `icon-192.png`, `icon-512.png`, `maskable-512.png`, `site.webmanifest`.

## 2. Clear Space
Keep a clear zone of **1 × `S`** around the logo on all sides, where **`S`** equals the height of the middle inspection stratum (`44 units` on the `256` symbol canvas, or roughly **20 %** of the symbol height). In horizontal lockups, the gap between the symbol and the `WAF STUDIO` wordmark is locked to `1.4 × S`.

## 3. Minimum Size
| Version | Screen | Print | Notes |
|---|---|---|---|
| **Horizontal lockup** | `120 px` wide (`28 px` tall) | `30 mm` wide | Below `120 px` wide, switch to symbol-only |
| **Stacked lockup** | `80 px` wide | `20 mm` wide | For square cards and cover pages |
| **Symbol (standard cut)** | `28 px` | `7 mm` | `waf-studio-symbol-color.svg` |
| **Symbol (small-size cut)** | `16 px` – `24 px` | `4 mm` | Use `waf-studio-symbol-small.svg` / `public/favicon.svg` (widened 24–26 unit channels) |

## 4. Colour Palette

| Name | Role | HEX | RGB | CMYK | Pantone (approx.) | Contrast |
|---|---|---|---|---|---|---|
| **Studio Cobalt** | Right 3 inspection strata, `STUDIO` wordmark, UI `--accent` | `#0060C7` | `0, 96, 199` | `100, 52, 0, 22` | `285 C` | `6.1 : 1` on `#FFFFFF` |
| **Deep Armour Navy** | Left solid shield plate (light backgrounds) | `#0B3566` | `11, 53, 102` | `89, 48, 0, 60` | `295 C` | `11.8 : 1` on `#FFFFFF` |
| **Studio Ink** | `WAF` wordmark, one-colour dark logo, UI `--text` | `#1D1D1F` | `29, 29, 31` | `6, 6, 0, 88` | `Black 6 C` | `16.9 : 1` on `#FFFFFF` |
| **Electric Sky** | Right 3 inspection strata & `STUDIO` on dark backgrounds (`--accent` dark) | `#4C9DFF` | `76, 157, 255` | `70, 38, 0, 0` | `279 C` | `7.6 : 1` on `#111113` |
| **Studio Dark Canvas** | Dark-mode background & app-icon tile (`--canvas` dark) | `#111113` | `17, 17, 19` | `11, 11, 0, 93` | `Black 7 C` | — |

### Approved Background Pairings
- **Light surfaces (`#FFFFFF`, `#F5F5F7`)**: Full-colour master (`#0B3566` left plate + `#0060C7` strata; `#1D1D1F` `WAF` + `#0060C7` `STUDIO`), one-colour Cobalt (`#0060C7`), or one-colour Black (`#000000`).
- **Dark surfaces (`#111113`, `#1C1C1F`)**: Dark-surface master (`#FFFFFF` left plate + `#4C9DFF` strata; `#FFFFFF` `WAF` + `#4C9DFF` `STUDIO`, optically thinned by 2 units against irradiation) or one-colour White (`waf-studio-symbol-white-thinned.svg`).
- **Compact UI header & login card (`16–24 px`)**: One-colour `currentColor` (`icon('logo')` in `public/js/icons.js`, coloured via CSS `--accent`).

## 5. Typography & Construction
- **Logo wordmark**: Custom-constructed geometric outlines (zero `<text>` font dependencies). `WAF` is set in heavy weight (`21–22 unit` stems, exact `75°` diagonals, `-6 unit` optical kerning between `W` and `A`); `STUDIO` is set in medium weight (`16–17 unit` stems, true circular `A` arcs, `+2 unit` optical overshoot on `S`, `U`, `O`).
- **UI & Documentation typography**:
  - **UI Sans**: `-apple-system, BlinkMacSystemFont, "SF Pro Text", "Segoe UI Variable Text", "Segoe UI", system-ui, sans-serif`
  - **Code / Rule DSL / Evidence Monospace**: `ui-monospace, "SF Mono", "Cascadia Code", Consolas, monospace`

## 6. Misuse (Don'ts)
- Don't stretch, skew, or alter the `15°` crown or `45°` lower shield facets.
- Don't close or narrow the vertical spine gap or the two horizontal strata gaps.
- Don't swap the left and right halves (left is solid armour; right is the 3-stage output pipeline).
- Don't add drop shadows, bevels, or non-approved gradients.
- Don't retype `WAF STUDIO` in a system font in place of the outlined lockup artwork.

## 7. Handover & Verification Notes
- **Audit**: All master SVG files score **100/100** in `svg_audit.py` (exact `0°`, `15°`, `45°`, `75°`, `90°` angles, outlined paths, zero `<text>` or raster elements, real negative-space gaps).
- **Legal / Trademark note**: This design is original geometric artwork created for WAF Studio; a formal trademark & reverse-image search is always recommended prior to commercial registration.

