# Diagrams

The five figures in the root [`README.md`](../../README.md), and the script that draws
them.

## Regenerating

```bash
cd backend && . .venv/bin/activate   # Windows: .\backend\.venv\Scripts\Activate.ps1
python ../docs/diagrams/gen_diagrams.py
```

Pillow is the only requirement, and it is already a backend dependency. No network, no
Graphviz, no Mermaid renderer, no Node — `git clone` and one command is the whole story,
which is the same constraint the product itself works under.

Everything is drawn at 3× and downscaled with LANCZOS, so the PNGs stay sharp at the
width GitHub renders them. The palette comes from the console's own light theme in
[`frontend/src/styles/index.css`](../../frontend/src/styles/index.css); if that changes,
change the constants at the top of the script to match, so the docs and the product keep
looking like the same thing.

## Type sizes, and why they are where they are

Every size lives in the `TYPE` dict at the top of the script, in logical pixels, and the
sizes are deliberately large relative to the canvas. GitHub renders a README image into
a column about 880px wide, so a 1180px-wide figure is displayed at roughly three
quarters size — an 11px label arrives on screen at about 8px, which is what made the
first version hard to read. **Making the canvas bigger does not help**: the browser
simply scales it down further. The only thing that changes how large the text *reads* is
its size relative to the layout around it, so that is the knob, and the boxes were grown
to suit rather than the other way round.

Raising a size can push a caption out through the side or the bottom of its box. The
script refuses to pretend otherwise: `box()` and `fits()` measure every string against
the space it has, collect everything that does not fit, print each one with the number
of pixels it is over by, and exit non-zero. The figures are still written first, because
seeing the broken output is most of how an overflow gets fixed — the non-zero exit is
what stops it being committed.

Free-floating text is not covered by that check, and one label on `fig5` sits in the
channel between the two panels with nothing to clip against. It is measured explicitly
for that reason. If you add another label outside a box, measure it the same way.

## The figures

| File | Shows | Why it is here |
|---|---|---|
| `fig1_architecture.png` | The components and how a request moves through them | Orientation — the one picture somebody needs before reading anything else |
| `fig2_readonly.png` | The four layers of the read-only guard, and how the claim is tested | The defining constraint, and the claim a reader is most entitled to doubt |
| `fig3_pipeline.png` | Collection through to findings, around the normalised model | Explains why a check written once runs on thirteen platforms |
| `fig4_path.png` | The two axes of a path answer, on the demonstration estate | The thing this tool does that the established products do not |
| `fig5_topology.png` | What runs, what it talks to, and how much it needs | Answers "where does this live and what will it cost me to run" |

## If you change one

The figures assert numbers — 104 checks, thirteen platforms, 283 conformance assertions,
the sizing tiers. Those are claims, and stale claims in a picture are worse than stale
claims in prose because nobody greps a PNG. When a count moves, update the script and
re-render in the same commit.
