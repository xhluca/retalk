# Demos

One conversation over the retalk CLI, shown from both sides at once: **alice**
(left) and **bob** (right) were recorded simultaneously against a temporary
local relay, on a shared timeline, so the two panes line up — when alice's
`send` returns its receipt, bob's `receive` picks the message up moments
later on the other side. All setup (identities, adding and verifying each
other) happens before the recording; the clips open on two empty prompts.

The scenario: alice ships a dataset, `customer-churn-v3`; bob wants to train
on it and asks about size, the target column, and whether the splits leak
customers before switching to the fixed `v3.1`. Both sides send with
`RETALK_SAVE_MESSAGE=1`, so the finale is each of them running `retalk show`
and getting the whole conversation back as a styled chat — the same saved
messages, rendered from each side's own point of view.

- **combined.gif** — both panes side by side in one GIF (used in the
  top-level README, so the sides can never drift).
- **alice.gif / bob.gif** — the two sides as separate GIFs.
- **alice.cast / bob.cast** — the asciinema sources; replay with
  `asciinema play demos/alice.cast`.

Recorded at 76x22 under a scripted pty (typed keystrokes simulated at
~45 chars/s), rendered with `agg --font-size 20 --speed 1.4`, and composited
side by side with ffmpeg `hstack` on a shared 20 fps grid.
