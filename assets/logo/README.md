# Warden — logo & brand mark

## Concept
The mark encodes Warden's core idea in one glyph:

- **Shield** — the sealed security boundary; *default-deny*.
- **Amber dot** — the contained, untrusted agent.
- **One arrow through one gate** — the agent's *only* egress is through the proxy checkpoint.
- **Amber → teal shift across the gate** — *secret-swap at the edge*: an untrusted placeholder
  goes in, a real credential comes out. The agent never holds the real secret.

## Files
| File | Use |
|---|---|
| `warden-mark.svg` | Primary icon (full color). App icon, social avatar, favicon source. |
| `warden-logo.svg` | Horizontal lockup: mark + `WARDEN` wordmark + tagline. README header, site nav. |
| `warden-mark-mono.svg` | Single-color line mark. Inherits `currentColor` — set CSS `color` per background. Favicons, stamps, embossing. |

## Palette
| Token | Hex | Role |
|---|---|---|
| Slate 800 | `#1E293B` | Shield (top of gradient) |
| Slate 950 | `#0B1220` | Shield (bottom of gradient) |
| Teal 400 | `#2DD4BF` | Gate, egress (trusted) |
| Amber 500 | `#F59E0B` | Agent, placeholder (untrusted) |
| Slate 900 | `#0F172A` | Wordmark (light backgrounds) |
| Slate 500 | `#64748B` | Tagline |
| Slate 100 | `#F1F5F9` | Wordmark / mono on dark backgrounds |

## Notes
- The wordmark uses an `Inter`/system geometric sans via `font-family`. For pixel-perfect
  distribution, outline the text to paths (e.g. in Inkscape/Illustrator) so it renders
  identically without the font installed.
- SVG is the source of truth. Rasterize as needed (e.g. `rsvg-convert -w 512 warden-mark.svg -o warden-512.png`).
