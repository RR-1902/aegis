# AEGIS interface design

## Brief

- **Subject:** a deterministic, explainable network intrusion detection system with a
  simulation-only response layer.
- **Audience:** faculty evaluating the project, students learning intrusion detection, engineers
  reading the code.
- **Primary job:** explain what AEGIS is and show, step by step, why each alert was raised, using
  only real data.
- **Direction from the owner:** a premium, futuristic cybersecurity product; narrative and
  step-by-step rather than a dashboard dump; as much motion as possible; every term and icon
  explained.

## Principles

1. **Show the working.** Every number comes from the API or from the engine's own constants. No
   invented throughput, latency or packet counts. Decorative elements (the hero instrument and
   packet stream) carry no claims.
2. **Tell it as a story.** The overview follows one real attack through ten stages, each with its
   module path, its terms explained inline, and a scene showing what AEGIS sees.
3. **Colour means something.** Aegis blue marks interaction and emphasis. The four risk colours
   mark risk and nothing else. Dashed outlines mark anything simulated.
4. **Motion answers scroll and action.** Smooth scrolling (Lenis), a pinned story driven by
   ScrollTrigger, word-by-word heading reveals, count-ups, and scenes that play when their stage
   becomes active. Only `transform` and `opacity` animate.

## Tokens

| Token | Value | Role |
| --- | --- | --- |
| Void | `#04060B` | Page background |
| Surface 1–3 | `#0B111D` `#0F1727` `#152034` | Panels, raised panels, tooltips |
| Line 1–3 | slate at 12%, 20%, 34% | Borders |
| Text, text 2, muted | `#EDF2FB` `#B3BED2` `#7D89A2` | Type |
| Aegis blue | `#5B8DFF`, light `#9BBCFF` | Interaction, emphasis |
| Low, medium, high, critical | `#45D0C4` `#F6BF3C` `#FF8445` `#FF4A6E` | Risk only |

Type: **Hubot Sans** (GitHub's mechanical display face, wide setting) for headlines and numbers,
**Mona Sans** for prose and controls, **Geist Mono** for machine values. All self-hosted.

Radii: 8–10px on controls, 12–22px on panels, never capsules. Status lights are bordered rings,
never solid blinking dots. Surfaces are solid; no glass or backdrop blur. The fixed top bar is
transparent with a soft fade behind it once the page scrolls.

## Page structure

```
Overview
  top bar        mark · section links · API ring · console
  hero           headline, lead, three actions · lens instrument · packet stream
  about          what AEGIS is · the name · four pillars · five real numbers
  story          pinned: progress · stage text with inline terms · scene (10 stages)
  rules          two rule cards · points to action · SAFE_MODE note
  rule lab       inputs · live verdict from the browser copy of the engine
  simulate       five scenarios run by the real pipeline · latest stored event trace
  glossary       25 terms with icons, filterable
  under the hood architecture · stack
  scope          does today · not yet
  closing        call to action

Event ledger  (#/ledger?risk=&status=&event=)
  simulate · distribution · filters · event list · inspector
```

## Motion budget

Measured on the production build with the CPU throttled 4x (`scratchpad/perf.py` in the build
session): scrolling the whole overview gives a median frame of 16.7 ms, a 95th percentile of
50 ms and 3 frames over 100 ms out of 819. Looping animations live only in the hero, the story's
active scene and the status pulses, and pause when off screen. Never set a custom property on a
large ancestor per frame: it restyles every descendant (this cost 140 ms frames before it was
removed from the story progress bar).
