# Hyperframes Composition Brief: Sentinel Loop (Tanaka)

## Objective
Create a short launch-style brag video for Sentinel Loop — a governance broker
for AI agents, told through its own takeout-restaurant metaphor, played
completely straight.

## Output
- Composition directory: `brag-output/composition/`
- Rendered video: `brag-output/brag.mp4`
- Format: landscape — 1920x1080
- Duration: 22 seconds (final; extended for reading-time floors)

## Source Material
- Project root: /home/user/Tanaka
- Primary files read: README.md, sentinel_slice/console/static/index.html
  (the real console UI + palette), PROGRESS.md, SPEC.md
- Product name: Sentinel Loop (operator console codename: Tanaka)
- Tagline / strongest claim: every order — fulfilled **or refused** — produces
  a hash-chained, Ed25519-signed receipt verifiable offline; a prompt-injected
  order spawns zero processes and its rejection is itself a signed receipt.
- Key UI or visual moment to recreate: the Operator Console (header
  "Sentinel Loop — Operator Console", sienna-underlined header, tab nav
  Capabilities · Menu · Policies · Activity, the "Add a menu item" card) and
  the real terminal output of `run_slice` / `verify_ledger.py`.
- Copy that must appear verbatim:
  - `injected: accepted=False reason=OFF_MENU`
  - `OK verified=2`
  - "Sentinel Loop — Operator Console"
  - "Every order leaves a receipt. Even the refused ones."

## Creative Direction
- Tone preset: polished
- Creative direction: a restaurant metaphor played completely straight — calm
  confidence, receipt-paper warmth, terminal-real evidence
- Interpretation: fewer scenes, longer holds, soft transitions; wit lives in
  the copy and the one red OFF_MENU stamp, never in wacky motion
- Angle: a serious security architecture that talks like a diner — menus,
  cashiers, chefs, receipts. The proudest artifact is a rejection: a prompt
  injection blocked with zero processes spawned, receipted, signed,
  verifiable offline.
- Hook: "Your AI agent wants your keys." → "Don't give it keys." → "Give it
  a menu." (sienna)
- Outro / punchline: `OK verified=2` in green, then "Sentinel Loop — Every
  order leaves a receipt. Even the refused ones." with sub-line
  "271 tests passing · no LLM inside · verify offline with a public key"
- Avoid:
  - Generic SaaS language
  - Abstract filler visuals
  - Unrelated visual redesign (keep the project's warm-paper identity)

## Visual Identity
- Background: #f4f1ea (paper); cards #fffdf8
- Text: #2c2520 ink; muted #6b6157; hairlines #d8d0c4
- Accent: #a0522d sienna; ok #2e7d32; bad #b00020; warn #b26a00
- Display font: Georgia, "Times New Roman", serif (the console's real font)
- Body font: Georgia serif; terminal text "Courier New" monospace
- Visual references from the project: console header w/ 3px sienna
  bottom-border, tab nav with sienna active underline, receipt-paper cards,
  risk pills, `.flag` warm warning box

## Storyboard
Use the storyboard in `brag-output/brag-plan.md` as the creative contract.

Scene summary:
1. The hook — 3.5s — three serif lines land one by one; "Give it a menu." in
   sienna is the turn
2. The takeout model — 4.5s — receipt strip, four stamps on the beat grid:
   DINER orders / CASHIER checks / CHEF cooks / RECEIPT signed; sub-line
   "The agent holds zero credentials."
3. The console — 4s — recreated Tanaka console; typing into "Add a menu
   item", cursor clicks the sienna "Add to menu" button; caption "A
   compliance officer curates agent power. No code."
4. The injection — 4.5s — dark terminal card; poisoned `forward_inbox` order;
   `injected: accepted=False reason=OFF_MENU`; red OFF_MENU stamp beat-locked
   at ~12.65s; kicker "Zero chef processes spawned. The rejection is itself a
   signed receipt."
5. Verify + logo — 3.5s — `verify_ledger.py` types, `OK verified=2` green on
   ~17.91s cue; final card "Sentinel Loop" + punchline + stats sub-line,
   music fades.

## Audio
- Audio role: warm confident bed with restrained, motion-matched accents
- Audio arc: opens assured, ticks along with stamps and typing, ducks for one
  dry OFF_MENU hit at ~12.65s, resolves with a green-OK tick, fades out over
  the final 1.5s
- Music: `assets/music/happy-beats-business-moves-vol-11-by-ende-dot-app.mp3`
  (~114.8 BPM)
- Music treatment: start 0s, volume ~0.35, duck slightly under the OFF_MENU
  stamp, fade out 18.5→20s
- Music cue guidance: bundled preset
  `assets/music/cues/happy-beats-business-moves-vol-11-by-ende-dot-app.music-cues.json`.
  Strong cues: 1.60s (hook line 2), 3.70s (scene 2 entry), 12.65s (OFF_MENU
  stamp — the one big beat-lock), 17.91s (OK verified), 22.65s→use ~19.5s
  equivalent for logo settle (video ends at 20s; prefer natural timing for the
  logo if no good cue fits). Beat grid ~0.525s spacing; stamps in scene 2 snap
  to every other beat (3.70 / 4.75 / 5.80 / 6.86s) so labels meet the 0.8s
  settled floor.
- Audio-reactive treatment: subtle; music RMS/bass may breathe the
  paper-card shadow/presence and warm the background slightly. No waveforms,
  no equalizers, no pulsing type.
- Audio-coupled moments:
  - Scene 1 — lines 2-3 land on beats, soft paper tick per line
  - Scene 2 — four stamp thunks on the beat grid
  - Scene 3 — typed text with randomized keypress sounds; one clean click on
    "Add to menu"
  - Scene 4 — terminal lines tick in; one dry impact on the OFF_MENU stamp
    (beat-locked 12.65s)
  - Scene 5 — typed command keypresses; gentle positive accent on the green
    `OK verified=2`
- SFX selection guidance: match the gesture — stamp/impact family for stamps
  (impactSoft_medium / impactWood), interface/ui clicks for the cursor click,
  keyboard/keypress-*.wav randomized for typing, one bell-ish positive accent
  (bong_001 or impactBell, quiet) for the OK. Polished tone: 0.55-0.7 volume,
  sparse, nothing aggressive. The OFF_MENU hit is the only loud moment.
- SFX analysis guidance: `~/.claude/skills/brag/assets/sfx/sfx-analysis.md` —
  prefer low high-frequency-risk files for repeated/polished moments.
- Exact SFX choice: Hyperframes chooses filenames, timestamps, density, and
  volume based on the implemented animation.
- Audio files: copy chosen music + SFX into `brag-output/composition/assets/`

## Hyperframes Instructions
Load the composition-building Hyperframes domain skills — `hyperframes-core`,
`hyperframes-animation`, `hyperframes-creative`, `hyperframes-keyframes`,
`hyperframes-cli`. /brag is its own workflow: do not enter the `hyperframes`
entry-point intent interview and do not route into its generic promo /
launch-video workflow. Prefer native Hyperframes conventions over anything in
`/brag`.

Requirements:
- Show at least one real UI, copy, or visual element from the source project
  (the console recreation and the verbatim terminal lines).
- Keep all text readable in the final render (settled holds: ≥0.8s labels,
  ~0.3s/word sentences).
- Keep the video at 20 seconds.
- Include the planned music/SFX layer.
- Treat cue metadata as optional timing hints; readability and story first.
- 1-3 strong cue locks max: OFF_MENU stamp (12.65s) is mandatory; OK verified
  (17.91s) if it reads well.
- Use local assets only; no external origins (fitting — the console itself
  loads nothing from the internet).
- Run `hyperframes check` before render — it is brag's single gate.
