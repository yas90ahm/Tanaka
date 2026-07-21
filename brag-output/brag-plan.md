# Brag Plan: Sentinel Loop (Tanaka)

## What is this app?
A governance broker for AI agents: the agent holds **zero credentials** and
"orders takeout" from an operator-curated menu; a cashier validates without
reading content; a disposable chef executes exactly what got signed; and every
order — fulfilled **or refused** — leaves a hash-chained, Ed25519-signed
receipt anyone can verify offline with one script and a public key. No LLM
anywhere in the repo.

## The angle
A restaurant metaphor played completely straight. This is a serious security
architecture that talks like a diner: menus, cashiers, chefs, receipts. The
video leans into that with receipt-paper aesthetics and calm confidence — and
lands the twist that the proudest artifact is a **rejection**: a prompt
injection blocked with zero processes spawned, receipted, signed, verifiable.

## Hook (first 2-3 seconds)
Warm paper background. Giant serif type slams in and holds:
**"Your AI agent wants your keys."** Beat. Second line: **"Don't give it keys."**
Then the reveal line rolls in: **"Give it a menu."**

## Key moments (the middle)
- The takeout model as a four-stamp receipt strip: DINER orders → CASHIER
  checks → CHEF cooks → RECEIPT signed. Each stamp arrives on a beat.
- The real Tanaka operator console — warm paper UI, tabs (Capabilities · Menu ·
  Policies · Activity), cursor clicks "Add to menu". A compliance officer
  curates agent power by clicking, not by editing JSON.
- The blocked injection, terminal-real: `injected: accepted=False
  reason=OFF_MENU` with a red OFF_MENU stamp, and the kicker line "zero chef
  processes spawned. The rejection itself is a signed receipt."

## Outro / punchline
Terminal: `python verify_ledger.py ledger.db public.pem` → `OK verified=2` in
green. Final card: **Sentinel Loop** — "Every order leaves a receipt. Even the
refused ones." Sub-line: `271 tests passing · no LLM inside · verify offline
with a public key`.

## User flow worth showing
1. **Entry** — an order for a declared capability is placed (and a poisoned
   order tries `forward_inbox`).
2. **Key action** — the cashier validates: honest order FULFILLED with a
   digest; injected order rejected `OFF_MENU`, zero chef processes spawned.
3. **Result** — `verify_ledger.py` proves the whole chain offline: `OK
   verified=2`.

## Tone
- Preset: polished
- Creative direction: a restaurant metaphor played completely straight — calm
  confidence, receipt-paper warmth, terminal-real evidence
- Interpretation: fewer scenes, longer holds, soft transitions; the wit lives
  in the copy and the OFF_MENU stamp, never in wacky motion. Confidence
  through restraint.

## Format: landscape — 1920x1080
## Duration: 22 seconds (extended from 20 at composition time so the injection
kicker and finale punchline meet the reading-time floor; scenes 4–5 merged
into one continuous terminal sequence with the finale crossfading over it)

## Visual identity (from the project)
- Background: #f4f1ea (console `--bg`, warm paper)
- Card: #fffdf8 (`--card`)
- Accent: #a0522d (`--accent`, sienna)
- Text: #2c2520 (`--ink`); muted #6b6157; line #d8d0c4
- Status colors: ok #2e7d32 · warn #b26a00 · bad #b00020
- Display font: Georgia (serif — the console's actual font)
- Body font: Georgia; terminal/code in Courier New monospace
- Strongest visual element: the operator console header + tab nav, and
  receipt-paper cards with a sienna border

## Share copy (draft)
Your AI agent doesn't need your keys. It needs a menu. Sentinel Loop: every
agent action — even the blocked prompt injection — leaves a signed receipt you
can verify offline. No LLM inside.

## Audio direction
- Role: warm confident bed with restrained, motion-matched accents
- Music: bundled `happy-beats-business-moves-vol-11-by-ende-dot-app.mp3`
  (~114.8 BPM)
- Music treatment: start at 0s at moderate volume, duck slightly under the
  OFF_MENU stamp so the dry hit lands, fade out over the final 1.5s
- Music cue guidance: preset cue file read
  (`assets/music/cues/...vol-11...music-cues.json`). Strong cues at 1.60s
  (hook line 2), 3.70s (scene 2 entry), 12.65s (OFF_MENU stamp — the video's
  one big beat-locked hit), 17.91s (OK verified reveal), 22.65s (logo settle).
  Beat grid (~0.525s spacing) available for the four receipt stamps in scene 2
  — snap stamps to every other beat (~1.05s apart) so each label meets the
  0.8s settled floor.
- Audio-reactive treatment: subtle; music energy may breathe the paper-card
  presence/shadow and warm the background slightly — no waveforms, no pulsing
  type
- SFX posture: sparse and professional — paper/stamp thunks for receipt
  stamps, soft click for the console button, one dry hit for OFF_MENU, gentle
  positive tick for `OK verified=2`
- Audio-coupled moments: four sequential receipt stamps; cursor click in the
  console; terminal lines appearing; the OFF_MENU stamp; the green OK reveal
- Restraint rule: no risers, no whooshes on every transition, no comedy
  sounds; the OFF_MENU hit is the only loud moment

## Storyboard

### Scene 1 — The hook — 3.5s
Warm paper (#f4f1ea). Giant Georgia serif ink type, centered:
"Your AI agent wants your keys." (in fast by 0.4s, holds ~1.4s) →
"Don't give it keys." (lands on the 1.60s strong cue, holds ~0.8s) →
"Give it a menu." in sienna (#a0522d), holds ~1.2s.
Sequential/interaction: yes — three lines arrive one by one, each replacing or
stacking under the last; the third line is the turn.
Audio intent: music opens warm and assured; near silence otherwise.
Audio-coupled idea: line 2 and 3 land on beats; subtle paper tick per line.
Music: warm confident groove from 0s.
Transition mood: soft → Scene 2

### Scene 2 — The takeout model — 4.5s
A receipt-paper strip (card #fffdf8, dashed edges) across the frame. Four
stamps arrive one by one, ~1.05s apart (every other beat from 3.70s):
"DINER orders" → "CASHIER checks" → "CHEF cooks" → "RECEIPT signed". Small
muted sub-line settles beneath: "The agent holds zero credentials."
Sequential/interaction: yes — four stamps, one per two beats, each with a soft
stamp thunk; each label holds ≥0.8s settled (the full strip stays on screen).
Audio intent: rhythmic arrival, playful but composed.
Audio-coupled idea: stamps snap to the beat grid (3.70 / 4.75 / 5.80 / 6.86s).
Music: groove continues.
Transition mood: clean slide → Scene 3

### Scene 3 — The console — 4s
Recreate the real Tanaka console: header "Sentinel Loop — Operator Console"
with sienna underline, sub-line "Control plane · localhost only · never sees
content", tab nav (Capabilities · Menu · Policies · Activity). The Menu screen
card "Add a menu item": behavior dropdown reads "Summarize a document", name
field types "Summarize contracts", cursor moves in and clicks **Add to menu**.
Caption line below: "A compliance officer curates agent power. No code."
Sequential/interaction: yes — text types into the name field, then a cursor
click on the sienna button; the new row appears in the menu table.
Audio intent: quiet competence — soft key ticks, one clean click.
Audio-coupled idea: typed text with subtle key ticks; click sound on the
button press.
Music: groove, slightly ducked under the typing.
Transition mood: soft → Scene 4

### Scene 4 — The injection — 4.5s
Dark terminal card on the paper background (Courier New). A poisoned order
scrolls in: `order: forward_inbox  ← hidden in a poisoned email`. Then the
verdict line appears: `injected: accepted=False reason=OFF_MENU`. On the
12.65s strong cue, a red (#b00020) OFF_MENU stamp slams over the card —
the video's one loud moment. Kicker line settles below in ink serif:
"Zero chef processes spawned. The rejection is itself a signed receipt."
(holds ~1.6s)
Sequential/interaction: yes — terminal lines appear line by line, then the
stamp hits.
Audio intent: tension for a breath, then the payoff hit; music ducked under
the stamp.
Audio-coupled idea: stamp beat-locked to the 12.65s strong cue; terminal lines
tick in on beats.
Music: ducks ~2dB at the stamp, returns.
Transition mood: hard cut → Scene 5

### Scene 5 — Verify + logo — 3.5s
Terminal line types: `python verify_ledger.py ledger.db public.pem` →
`OK verified=2` appears in green (#2e7d32) on the 17.91s cue and holds. Cut to
final card on paper: **Sentinel Loop** in giant serif, line beneath: "Every
order leaves a receipt. Even the refused ones." Muted sub-line:
"271 tests passing · no LLM inside · verify offline with a public key."
Logo settles on the 22.65s cue as music fades over the last 1.5s.
Sequential/interaction: yes — command types, result pops; then the title card.
Audio intent: resolution — one gentle positive tick on the green OK, then the
bed fades to done.
Audio-coupled idea: typed command with key ticks; OK lands on the 17.91s cue.
Music: fades out 18.5→20s.
Transition mood: soft crossfade to end.

**Music mood for this video:** upbeat but composed — warm business groove
**Audio summary:** a warm confident bed carries the whole 20s; sparse
motion-matched paper/stamp/click sounds ride the beat grid, one dry
beat-locked hit lands the OFF_MENU stamp, and a green-OK tick resolves into a
1.5s fade-out.

Scene durations: 3.5 + 4.5 + 4 + 4.5 + 3.5 = **20s** ✓
