---
version: "superdesign-alpha"
name: "Void Index Gallery"
description: "Near-black flat gallery system with a single edge-to-edge square navbar, transparent screenshot-cards, and a low-contrast gray-on-black text ramp with one warm coral utility accent."
colors:
  background: "#181818"
  surface: "#000000"
  surface-modal: "#121212"
  text-primary: "#FFFFFF"
  text-secondary: "#B3B3B3"
  text-tertiary: "#939393"
  text-contrast-50: "#D9D9D9"
  border: "#242424"
  border-strong: "#333333"
  accent-coral: "#F37A7A"
typography:
  display-lg:
    fontFamily: "Inter"
    fontSize: "30px"
    fontWeight: 600
    lineHeight: "1.3"
    letterSpacing: "-0.3px"
  headline-md:
    fontFamily: "Inter"
    fontSize: "22px"
    fontWeight: 600
    lineHeight: "1.2"
    letterSpacing: "-0.2px"
  body-md:
    fontFamily: "Inter"
    fontSize: "17px"
    fontWeight: 400
    lineHeight: "1.4"
  label-md:
    fontFamily: "Inter"
    fontSize: "17px"
    fontWeight: 400
    lineHeight: "1.2"
    letterSpacing: "-0.2px"
  accent-serif:
    fontFamily: "Times New Roman"
    fontStyle: "normal"
    role: "occasional editorial/serif label contrast within card media, not body copy"
spacing:
  base: "8px"
  gap-grid: "44px 40px"
  gap-tight: "15px"
  gap-loose: "40px"
  section-padding: "44px"
rounded:
  control: "6px"
  card: "5px"
  pill: "50px"
components:
  button-nav-cta:
    background: "rgba(255, 255, 255, 0.2)"
    text-color: "#D8D8D8"
    radius: "6px"
    height: "33px"
    padding: "6px 12px"
    hover-background: "rgba(255, 255, 255, 0.3)"
    hover-text-color: "#FFFFFF"
  button-nav-link:
    background: "transparent"
    text-color: "#B3B3B3"
    radius: "0px"
    height: "33px"
    padding: "0px"
  button-secondary:
    background: "#282828"
    text-color: "#B3B3B3"
    radius: "6px"
    height: "40px"
    padding: "12px 16px"
  button-link-danger:
    background: "transparent"
    text-color: "#F37A7A"
    radius: "0px"
    height: "45px"
    padding: "0px"
  card-showcase:
    background: "transparent"
    radius: "5px"
    padding: "0px"
    border: "1px solid #242424"
  card-heading-only:
    background: "transparent"
    radius: "0px"
    padding: "0px"
---
# Void Index Gallery
Source: https://minimal.gallery/the-content-architecture/

## Overview
This is a minimalist, dark-mode-default editorial index — flat design with zero elevation cues (no shadows, no blur, no glass) built almost entirely from value contrast on a near-black field (`#181818`/`#000000`, ~65%+9% of rendered pixels). Structure is Swiss/International in spirit: a strict column grid, one weight of sans (Inter) doing all typographic work, and a strict low-contrast gray text ramp (`#B3B3B3` body, `#939393` muted, `#FFFFFF` emphasis) standing in for color. The only saturated note anywhere in the system is a single coral utility label — everything else is grayscale value, making this a monochromatic system where hierarchy comes from lightness steps, not hue.

## Composition
The first screen opens on an edge-to-edge black navbar, followed immediately by a large two-column detail header (title + metadata block on a bare `#181818` canvas, left-aligned) paired with an oversized bordered screenshot-card on the right — this single card carries all the color and texture on the page. Below the fold, density increases sharply: a 4-column, 3-row uniform card grid of further screenshots runs the full body, then a plain-text footer link cluster closes the page. The deliberate choice is restraint over ornament: nearly the entire canvas is unstyled flat black/dark-gray, rejecting gradients, shadows, or accent color as hierarchy tools in favor of pure typographic scale and whitespace — color is reserved entirely for the embedded card media, never for chrome.

## Colors
`#181818` is the dominant page background (declared area 91.3%), with true `#000000` used specifically for the navbar and footer/darkest bands (pixel-field ~65%, declared area 6.8%) — the rebuild should treat `#181818` as the base canvas and `#000000` as a deliberately darker structural layer, not an error. Text sits on a three-step gray ramp: `#FFFFFF` for emphasis/contrast text, `#B3B3B3` as the default body/label ink, `#939393` for low-contrast secondary copy, and `#D9D9D9` as an intermediate contrast step. Borders use `#242424` (default) and `#333333` (strong) as hairline dividers between cards and sections — never a filled surface. The single coral accent (`#F37A7A`) is rationed to one text-only destructive/utility link and does not otherwise appear; all card imagery is left to carry whatever color it contains, uncontrolled by the shell.

## Typography
One family, Inter, carries the entire hierarchy: a display size at 30px/600/lh 1.3/ls -0.3px for the page's main title, a headline size at 22px/600/lh 1.2/ls -0.2px for card and section titles, and a body/label size shared at 17px (body regular lh 1.4, label lh 1.2 with -0.2px tracking) for everything else — metadata, nav items, footer links. There is no separate small-caption size; hierarchy is built from weight (400 vs 600) and color-value (white vs the three grays) rather than a wide size scale. A Times New Roman serif appears only inside embedded card media as an occasional accent face, never in the shell's own UI chrome.

## Layout
The primary content grid is 4 columns with a 44px/40px (row/column) gap, running 12 items across 3 rows of 4 — a strictly uniform card grid, not bento or masonry: every tracked row reads `[22 / 22 / 22 / 22]`, meaning all cards are equal width. This uniform-card-grid pattern repeats at the top of the page too, in the detail header's own showcase card, which is internally divided into image-only bands rather than mixed spans. Spacing is built on an 8px-derived scale with the small values (15px, 18px, 20px) used for internal card/list rhythm and the larger values (40px, 44px) for grid gutters and section padding. Cards themselves carry zero padding — content bleeds to the card edge — with only a 5px corner radius and hairline border defining the container; the layout is fully desktop-fixed here at 1920px reference width with the grid columns as the only responsive lever.

## Components
- **Navbar** — top of page, full viewport width (1920px measured, 0px left/right inset), 77px tall, square corners (0px all four), sticky, solid `#000000` fill, 8 items total (nav links + logo wordmark + utility icons). No pill, no rounding, no inset margin — this is a hard edge-to-edge square bar, not a floating capsule.
- **Nav CTA button** — right side of navbar (or embedded in demo card top bars), 1 per bar: `rgba(255, 255, 255, 0.2)` translucent fill, `#D8D8D8` text, 6px radius (slightly-rounded), 33px height, 6px/12px padding; hover brightens fill to `rgba(255, 255, 255, 0.3)` and text to `#FFFFFF`.
- **Nav text links** — ×13 across nav rows, transparent background, `#B3B3B3` text, 0px radius (sharp, no container), 33px height, no padding — pure text buttons.
- **Secondary/utility button** — appears within demo/showcase card media (e.g. "GET / ACCESS" style twin controls), ×3 measured: `#282828` fill, `#B3B3B3` text, 6px radius, 40px height, 12px/16px padding — a slightly-rounded solid gray pill-like control, distinct from the nav CTA's glass fill.
- **Danger/link button** — ×1, transparent background, coral `#F37A7A` text, 0px radius, 45px height, no padding — text-only, no container, the system's sole saturated-hue control.
- **Hero primary (observed)** — on the first screen, inside the large bordered showcase card, a pair of stacked small dark pill controls sit under the headline text over a light card background; these read as an observed near-white/light card with dark ~6px-radius button chips rather than a single dominant filled CTA — the shell itself has no large solid brand-color hero button; emphasis instead comes from the oversized card and its internal typographic contrast.
- **Showcase/screenshot card family** — ×11 in the main grid plus the header's large twin-panel card: transparent shell, 5px radius, 0px padding, 1px `#242424` border; anatomy is media-top-bleed (a full-bleed screenshot or illustration filling most/all of the card) with a heading and short body line either overlaid or immediately below — three rows of `[22/22/22]` or `[22/22/22/22]` width splits confirm uniform equal-width cards, not varied spans.
- **Heading-only card** — ×2, transparent, 0px radius, 0px padding, containing only a title line — used for lightweight list-style entries without media.
- **Footer** — bottom of page, transparent background, 22 text links arranged in labeled columns (site, resources, social) plus a small mark/logo block, no card treatment, no borders, sits directly on the `#181818`/`#000000` page field.

## Graphics & Effects
No blur, no glassmorphism, no soft shadows anywhere in the shell — elevation is communicated purely by hairline `#242424`/`#333333` borders separating flat surfaces. The only rich visual texture in the system lives inside the embedded showcase-card media itself: dense radial/circular typographic patterns and grayscale halftone-like illustration fills appear as the card's own content, not as a page-level background — treat these as per-card imagery, confined to each card's frame, never bleeding into the black shell around them. The overall page background stays a flat, unlit `#181818`/`#000000`, with zero gradient or mesh treatment applied at the page level.

## Motion
Interaction feedback is limited to short state transitions: `color 0.2s ease`, `opacity 0.2s ease`, `background 0.2s ease`, and `fill 0.2s ease` — all simple linear-feeling eases at a uniform 200ms, used for hover/focus shifts on buttons and links (e.g., the nav CTA's fill brightening on hover). Supplementary keyframe animations (spinner, pulse, formPlaceholderShimmer, filtersShow/Hide) exist for loading and filter-panel states rather than decorative motion — there is no scroll-linked parallax or entrance choreography evident; the system's motion vocabulary is strictly utilitarian and fast.

## Guardrails
- Never introduce drop shadows, glassmorphism blur, or elevation gradients — this system separates surfaces with hairline borders only.
- Do not recolor the shell: keep chrome grayscale (`#181818`/`#000000`/gray text ramp) and confine any saturated color, including the coral accent, to a single text link or to card-embedded media.
- Do not round the navbar — it is a square, edge-to-edge, sticky bar with 0px corners at full viewport width, not an inset or pill-shaped bar.
- Keep all grid cards equal-width and zero-padding with bleeding media; do not introduce bento-style mixed spans where the measured rows are uniform.
- Do not substitute the nav CTA's translucent glass fill for the hero's primary action — the hero's emphasis comes from card scale and internal button chips, not a large brand-filled button.
- Limit type to Inter for all shell UI; reserve any serif appearance strictly for imagery embedded inside cards.