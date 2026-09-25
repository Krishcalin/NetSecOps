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
