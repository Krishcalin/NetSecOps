#!/usr/bin/env python3
"""Render the README's architecture figures.

Pure Pillow, 3× supersampled and downscaled with LANCZOS, so the output is crisp at the
width GitHub renders it. No network, no graphviz, no build step beyond `python
gen_diagrams.py` — the same constraint the product itself works under, and the reason
these are regenerable by anyone who clones the repository.

Five figures, chosen for what somebody needs to *see* rather than for what is hardest to
draw:

1. `fig1_architecture` — the pieces and how a request flows through them.
2. `fig2_readonly` — the four-layer guard. The defining constraint of the product, and
   the one claim a reader is entitled to be sceptical about.
3. `fig3_pipeline` — collection to findings, with the normalised model in the middle
   where every engine reads it.
4. `fig4_path` — the two axes of a path answer, which is the thing this product does
   that the established tools do not.
5. `fig5_topology` — what actually runs, and what it talks to.

The palette is the console's own (`frontend/src/styles/index.css`), so the documentation
and the product look like the same thing.
"""

from __future__ import annotations

import os

from PIL import Image, ImageDraw, ImageFont

OUT = os.path.dirname(os.path.abspath(__file__))
S = 3  # supersample factor

#: Every type size in one place, in logical pixels.
#:
#: Sizes are relative to the canvas width, and that is the whole reason this dict
#: exists. GitHub renders a README image into a column about 880px wide, so a
#: 1180px-wide figure is displayed at roughly three quarters size and an 11px label
#: arrives on screen at about 8px. Enlarging the canvas does not help — the browser
#: just scales it down further — so the only lever that makes text bigger *as read* is
#: its size relative to the layout around it. These are about a fifth larger than the
#: first version for exactly that reason.
#:
#: Raising one of these can push text out of the box it sits in, which `box()` and
#: `fits()` refuse rather than allow: the generator fails loudly instead of writing a
#: figure with a caption hanging over its own border.
TYPE = {
    "title": 23,
    "subtitle": 14.5,
    #: The small uppercase label on a band or panel.
    "band": 12,
    #: A box's bold name, and the muted lines under it.
    "heading": 15.5,
    "detail": 13,
    #: Standalone callouts that are not inside a box.
    "note": 12.5,
}

#: Clear space kept inside a box before text may not go. Text wider than the box less
#: twice this is treated as an overflow even though it would technically still be
#: inside the border — a caption touching its own edge reads as a mistake.
PAD = 12.0

#: Collected by `fits()` and raised together at the end of a run. Reported all at once
#: rather than on the first failure: raising a type size usually breaks several boxes,
#: and fixing them one regeneration at a time is miserable.
_OVERFLOWS: list[str] = []

# ── palette, from the console's light theme ──────────────────────────────────
WHITE = "#FFFFFF"
BG = "#F6F7F9"
INK = "#14181D"
SUBTLE = "#5B6572"
BORDER = "#D7DBE0"
ACCENT = "#1D4ED8"
ACCENT_SOFT = "#E5EDFF"
OK = "#0F7B3F"
OK_SOFT = "#E3F5EA"
WARN = "#8A5A00"
WARN_SOFT = "#FDF2DC"
ERROR = "#B3261E"
ERROR_SOFT = "#FBE9E7"
PANEL = "#F0F2F5"

REG = ["C:/Windows/Fonts/segoeui.ttf", "C:/Windows/Fonts/calibri.ttf", "arial.ttf"]
BLD = ["C:/Windows/Fonts/segoeuib.ttf", "C:/Windows/Fonts/calibrib.ttf", "arialbd.ttf"]
SEM = ["C:/Windows/Fonts/seguisb.ttf"] + BLD
MON = ["C:/Windows/Fonts/consola.ttf", "cour.ttf"]


def _font(candidates: list[str], size: float) -> ImageFont.FreeTypeFont:
    for path in candidates:
        try:
            return ImageFont.truetype(path, int(size * S))
        except OSError:
            continue
    try:
        return ImageFont.load_default(int(size * S))
    except TypeError:  # Pillow < 9.2 has no size argument
        return ImageFont.load_default()


def reg(size: float):
    return _font(REG, size)


def bld(size: float):
    return _font(BLD, size)


def sem(size: float):
    return _font(SEM, size)


def mono(size: float):
    return _font(MON, size)


def width_of(text: str, font: ImageFont.FreeTypeFont) -> float:
    """How wide `text` renders, in logical pixels.

    Fonts are built at `size * S`, so every measurement comes back supersampled and has
    to be divided back down before it can be compared with a logical box width.
    """
    return font.getlength(text) / S


def fits(where: str, text: str, font: ImageFont.FreeTypeFont, available: float) -> None:
    """Record an overflow rather than drawing one.

    The alternative — trusting that the sizes still fit after someone changes them — is
    how a figure ends up with a caption lapping over its own border, which nobody
    notices until it is in a README on the internet.
    """
    used = width_of(text, font)
    if used > available:
        _OVERFLOWS.append(
            f"{where}: {text!r} needs {used:.0f}px, {available:.0f}px available "
            f"(over by {used - available:.0f}px)"
        )


class Canvas:
    """A small drawing surface in logical pixels; everything is scaled by `S`."""

    def __init__(self, width: int, height: int, bg: str = WHITE) -> None:
        self.w, self.h = width, height
        self.im = Image.new("RGB", (width * S, height * S), bg)
        self.d = ImageDraw.Draw(self.im)

    def rect(
        self,
        x: float,
        y: float,
        w: float,
        h: float,
        *,
        fill: str | None = None,
        outline: str | None = BORDER,
        width: float = 1.6,
        radius: float = 12,
    ) -> None:
        self.d.rounded_rectangle(
            [x * S, y * S, (x + w) * S, (y + h) * S],
            radius=int(radius * S),
            fill=fill,
            outline=outline,
            width=max(1, int(width * S)),
        )

    def text(self, x: float, y: float, s: str, f, *, fill: str = INK, anchor: str = "lm") -> None:
        self.d.text((x * S, y * S), s, font=f, fill=fill, anchor=anchor)

    def lines(
        self,
        cx: float,
        y: float,
        rows: list[str],
        f,
        *,
        fill: str = INK,
        lh: float | None = None,
        anchor: str = "mm",
    ) -> None:
        step = lh or (f.size / S * 1.45)
        for index, row in enumerate(rows):
            self.text(cx, y + index * step, row, f, fill=fill, anchor=anchor)

    def arrow(
        self,
        x1: float,
        y1: float,
        x2: float,
        y2: float,
        *,
        colour: str = SUBTLE,
        width: float = 1.8,
        head: float = 7,
        dashed: bool = False,
    ) -> None:
        if dashed:
            self._dashed(x1, y1, x2, y2, colour=colour, width=width)
        else:
            self.d.line([x1 * S, y1 * S, x2 * S, y2 * S], fill=colour, width=max(1, int(width * S)))
        self._head(x1, y1, x2, y2, colour=colour, size=head)

    def _dashed(self, x1, y1, x2, y2, *, colour, width, dash=7, gap=5) -> None:
        span = ((x2 - x1) ** 2 + (y2 - y1) ** 2) ** 0.5
        if span == 0:
            return
        ux, uy = (x2 - x1) / span, (y2 - y1) / span
        travelled = 0.0
        while travelled < span:
            end = min(travelled + dash, span)
            self.d.line(
                [
                    (x1 + ux * travelled) * S,
                    (y1 + uy * travelled) * S,
                    (x1 + ux * end) * S,
                    (y1 + uy * end) * S,
                ],
                fill=colour,
                width=max(1, int(width * S)),
            )
            travelled = end + gap

    def _head(self, x1, y1, x2, y2, *, colour, size) -> None:
        span = ((x2 - x1) ** 2 + (y2 - y1) ** 2) ** 0.5
        if span == 0:
            return
        ux, uy = (x2 - x1) / span, (y2 - y1) / span
        px, py = -uy, ux
        self.d.polygon(
            [
                (x2 * S, y2 * S),
                ((x2 - ux * size + px * size * 0.5) * S, (y2 - uy * size + py * size * 0.5) * S),
                ((x2 - ux * size - px * size * 0.5) * S, (y2 - uy * size - py * size * 0.5) * S),
            ],
            fill=colour,
        )

    def title(self, text: str, subtitle: str = "") -> None:
        self.text(self.w / 2, 36, text, bld(TYPE["title"]), anchor="mm")
        if subtitle:
            font = reg(TYPE["subtitle"])
            fits("figure subtitle", subtitle, font, self.w - 120)
            self.text(self.w / 2, 64, subtitle, font, fill=SUBTLE, anchor="mm")

    def band(self, x: float, y: float, label: str, *, fill: str = SUBTLE) -> None:
        """The small uppercase label that titles a panel."""
        self.text(x, y, label, sem(TYPE["band"]), fill=fill)

    def save(self, name: str) -> None:
        path = os.path.join(OUT, name)
        flat = self.im.resize((self.w, self.h), Image.LANCZOS)
        # These are flat-colour drawings: ~4k distinct values, nearly all of them
        # antialiasing between a dozen fills. An adaptive 256-colour palette is
        # indistinguishable by eye and roughly 60% smaller in the repository.
        flat.quantize(colors=256, method=Image.MEDIANCUT, dither=Image.NONE).save(
            path, "PNG", optimize=True
        )
        print(f"  {name}")


def box(
    c: Canvas,
    x: float,
    y: float,
    w: float,
    h: float,
    heading: str,
    rows: list[str],
    *,
    fill: str = WHITE,
    outline: str = BORDER,
    accent: str | None = None,
) -> None:
    """A labelled panel: bold heading, muted detail lines beneath.

    The geometry is derived from the type sizes rather than hardcoded, so raising a
    size moves the text that follows it instead of letting it collide with the line
    below. Both dimensions are checked: a caption can overflow a box sideways, and a
    third detail line can push out through the bottom, and neither is visible from the
    code that called this.
    """
    c.rect(x, y, w, h, fill=fill, outline=outline)
    if accent:
        c.rect(x, y, 4.5, h, fill=accent, outline=None, radius=2)

    heading_font, detail_font = sem(TYPE["heading"]), reg(TYPE["detail"])
    inner = w - 2 * PAD
    # The accent stripe eats into the usable width on the boxes that carry one.
    if accent:
        inner -= 4.5

    fits(f"box {heading!r} heading", heading, heading_font, inner)
    for row in rows:
        fits(f"box {heading!r} row", row, detail_font, inner)

    # Centred vertically rather than pinned to the top. The boxes grew to hold the
    # larger type and top-aligning left a band of dead space along the bottom of every
    # one of them, which reads as a layout that has come apart rather than as a
    # deliberate margin.
    step = TYPE["detail"] * 1.45
    gap = TYPE["heading"] * 0.55
    content = TYPE["heading"] + (gap + step * (len(rows) - 1) + TYPE["detail"] if rows else 0)

    if content + 2 * PAD > h:
        _OVERFLOWS.append(
            f"box {heading!r}: heading and {len(rows)} row(s) need "
            f"{content + 2 * PAD:.0f}px of height, box is {h:.0f}px"
        )

    top = y + (h - content) / 2
    c.text(x + w / 2, top + TYPE["heading"] / 2, heading, heading_font, anchor="mm")

    if rows:
        first = top + TYPE["heading"] + gap + TYPE["detail"] / 2
        c.lines(x + w / 2, first, rows, detail_font, fill=SUBTLE, lh=step)


# ─────────────────────── figure 1 — logical architecture ─────────────────────


def fig1_architecture() -> None:
    c = Canvas(1180, 692, BG)
    c.title(
        "Logical architecture",
        "One origin, one control plane, and a worker pool that is the only thing "
        "that ever reaches a device",
    )

    c.rect(60, 96, 1060, 158, fill=WHITE)
    c.band(78, 118, "BROWSER AND EDGE")
    # 244-wide boxes on a 260 pitch. The larger detail type needs about 30px more than
    # the first version, and it comes out of the gaps rather than out of the canvas —
    # a wider canvas would simply be scaled down further by the browser.
    box(c, 90, 136, 236, 100, "React console", ["Vite + TypeScript", "cookie session"],
        fill=ACCENT_SOFT, accent=ACCENT)
    box(c, 354, 136, 236, 100, "Caddy", ["TLS, security headers", "SPA + /api on one origin"])
    box(c, 618, 136, 236, 100, "FastAPI", ["RBAC, CSRF, audit", "OpenAPI at /api/v1"])
    box(c, 882, 136, 238, 100, "PostgreSQL 16", ["JSONB, INET, ltree", "Alembic migrations"])
    c.arrow(330, 186, 352, 186)
    c.arrow(594, 186, 616, 186)
    c.arrow(858, 186, 880, 186)

    c.rect(60, 282, 1060, 176, fill=WHITE)
    c.band(78, 304, "SERVICES — BUSINESS LOGIC, INDEPENDENT OF HTTP")
    services = [
        ("Inventory", ["devices, groups", "sites, tags"]),
        ("Credentials", ["AES-256-GCM vault", "never returned"]),
        ("Assessment", ["104 checks", "findings, risk"]),
        ("Vulnerability", ["CVE, KEV, EPSS", "end-of-life"]),
        ("Topology", ["layer-3 graph", "path analysis"]),
    ]
    for index, (name, rows) in enumerate(services):
        box(c, 90 + index * 206, 322, 196, 116, name, rows)

    c.text(590, 476, "services enqueue jobs and workers claim them — no worker ever serves HTTP",
           reg(TYPE["note"]), fill=SUBTLE, anchor="mm")

    c.rect(60, 496, 1060, 168, fill=WHITE)
    c.band(78, 518, "WORKERS AND ADAPTERS — THE ONLY PATH TO A DEVICE")
    box(c, 90, 536, 244, 110, "Job runner", ["claims work with", "FOR UPDATE SKIP LOCKED"])
    box(c, 372, 536, 244, 110, "Read-only guard", ["allow-list, deny-list", "see figure 2"],
        fill=OK_SOFT, accent=OK)
    box(c, 654, 536, 220, 110, "Adapters", ["SSH and vendor", "HTTPS APIs"])
    box(c, 904, 536, 216, 110, "Devices", ["13 platforms", "never written to"],
        fill=PANEL)
    c.arrow(338, 591, 370, 591)
    c.arrow(620, 591, 652, 591)
    c.arrow(874, 591, 902, 591)

    # Into the gap between Assessment and Vulnerability, so it points at the band rather
    # than appearing to single out one service.
    c.arrow(698, 254, 698, 316, dashed=True)

    c.save("fig1_architecture.png")


# ────────────────────── figure 2 — the read-only guarantee ───────────────────


def fig2_readonly() -> None:
    c = Canvas(1180, 650, BG)
    c.title(
        "The read-only guarantee",
        "Four layers, every one of them before transmission — nothing is filtered "
        "after the fact",
    )

    c.rect(60, 96, 1060, 322, fill=WHITE)

    # The four guard boxes widen to 214 on the same 222 pitch: the headings carry a
    # numeral and a separator as well as a name, and they are the tightest strings in
    # the set once the type grows.
    box(c, 92, 132, 206, 128, "1 · Allow-list", ["every adapter declares", "exactly what it may send"],
        fill=OK_SOFT, accent=OK)
    box(c, 322, 132, 206, 128, "2 · Deny-list", ["write verbs blocked even", "if an entry were wrong"],
        fill=OK_SOFT, accent=OK)
    box(c, 552, 132, 206, 128, "3 · GET-only REST", ["POST only for auth and", "POST-only vendor APIs"],
        fill=OK_SOFT, accent=OK)
    box(c, 782, 132, 206, 128, "4 · Guarded session", ["adapters hold no", "unchecked transport"],
        fill=OK_SOFT, accent=OK)

    for x in (298, 528, 758):
        c.arrow(x, 196, x + 22, 196, colour=OK)

    box(c, 1012, 132, 96, 128, "Device", ["read", "only"], fill=PANEL)
    c.arrow(988, 196, 1010, 196, colour=OK)

    c.rect(92, 292, 904, 104, fill=ERROR_SOFT, outline=ERROR)
    c.band(118, 320, "REJECTED BEFORE TRANSMISSION", fill=ERROR)
    c.lines(
        544,
        352,
        [
            "configure · write · copy · reload · commit · delete · ping · test aaa · debug",
            "anything an adapter did not declare, and anything with a side effect on the device",
        ],
        reg(TYPE["note"]),
        fill=ERROR,
    )
    c.arrow(544, 292, 544, 264, colour=ERROR)

    c.rect(60, 446, 1060, 172, fill=WHITE)
    c.band(78, 470, "HOW THE CLAIM IS CHECKED")
    box(c, 92, 488, 328, 112, "283 conformance assertions",
        ["what the guard decides", "the build fails on any"])
    box(c, 436, 488, 328, 112, "A fake SSH device",
        ["records every byte received", "checks what actually arrives"])
    box(c, 780, 488, 340, 112, "A tamper-evident audit log",
        ["every command, hash-chained", "so a customer can read it back"])

    c.save("fig2_readonly.png")


# ───────────────────────── figure 3 — assessment pipeline ────────────────────


def fig3_pipeline() -> None:
    c = Canvas(1180, 676, BG)
    c.title(
        "From a device to a finding",
        "Everything reads one normalised model, so a check written once runs on "
        "thirteen platforms",
    )

    box(c, 70, 114, 202, 106, "Collect", ["read-only commands", "and vendor API reads"])
    box(c, 296, 114, 202, 106, "Store", ["sealed artefact", "redacted snapshot"])
    box(c, 522, 114, 176, 106, "Parse", ["one parser", "per platform"])
    c.arrow(272, 167, 294, 167)
    c.arrow(498, 167, 520, 167)
    c.arrow(698, 167, 724, 167)

    c.rect(724, 100, 386, 134, fill=ACCENT_SOFT, outline=ACCENT, width=2.2)
    c.text(917, 132, "Normalised Config Model", bld(TYPE["heading"] + 2), anchor="mm")
    c.lines(
        917,
        166,
        [
            "vendor-neutral: interfaces, routes, AAA, crypto,",
            "firewall rules, NAT, users, logging, versions",
        ],
        reg(TYPE["detail"]),
        fill=SUBTLE,
    )

    # A bus rather than a fan: four splayed diagonals cross whatever caption sits under
    # them, and the point is that every engine reads the *same* thing.
    centres = [203.0, 465.0, 727.0, 989.0]
    c.d.line([917 * S, 234 * S, 917 * S, 276 * S], fill=SUBTLE, width=max(1, int(1.8 * S)))
    c.d.line(
        [centres[0] * S, 276 * S, centres[-1] * S, 276 * S],
        fill=SUBTLE,
        width=max(1, int(1.8 * S)),
    )
    for x in centres:
        c.arrow(x, 276, x, 318)

    c.text(80, 258, "every engine reads the same model — none of them parses anything",
           reg(TYPE["note"]), fill=SUBTLE, anchor="lm")

    engines = [
        ("Check engine", ["104 checks, JMESPath", "pass / fail / not evaluated"], ACCENT),
        ("Firewall analysis", ["shadowed, redundant,", "unused, any-any"], ACCENT),
        ("Vulnerability", ["CPE, CVE, KEV, EPSS", "end-of-life"], ACCENT),
        ("Topology", ["layer-3 graph", "path analysis"], ACCENT),
    ]
    for index, (name, rows, accent) in enumerate(engines):
        box(c, 82 + index * 262, 320, 242, 120, name, rows, accent=accent)

    c.rect(70, 480, 1040, 164, fill=WHITE)
    c.band(88, 504, "WHAT COMES OUT")
    box(c, 92, 522, 246, 106, "Findings", ["with a lifecycle,", "evidence and remediation"],
        fill=WARN_SOFT, accent=WARN)
    box(c, 354, 522, 238, 106, "Risk score", ["per device, with its", "components shown"])
    box(c, 608, 522, 238, 106, "Compliance", ["CIS, NIST, PCI, ISO", "pivoted by control"])
    box(c, 862, 522, 242, 106, "Reports", ["frozen at generation,", "dated artefacts"])
    for x in (215, 473, 727, 983):
        c.arrow(x, 446, x, 520)

    c.save("fig3_pipeline.png")


# ───────────────────────── figure 4 — the two axes ───────────────────────────


def fig4_path() -> None:
    c = Canvas(1180, 718, BG)
    c.title(
        "A path answer has two axes",
        "Routing and policy fail independently, so a single verdict has to lie "
        "about one of them",
    )

    c.band(90, 116, "THE QUESTION")
    c.rect(70, 132, 1040, 60, fill=WHITE)
    question = "can 10.10.10.50 reach 10.20.0.10 on tcp/443, and what decides?"
    question_font = mono(TYPE["detail"] + 1.5)
    fits("figure 4 question", question, question_font, 1040 - 2 * PAD)
    c.text(590, 162, question, question_font, anchor="mm")

    hops = [
        ("access switch", "no rulebase", "no decision", PANEL, SUBTLE),
        ("core switch", "no rulebase", "no decision", PANEL, SUBTLE),
        ("edge firewall", "INSIDE-IN permits", "and it translates", WARN_SOFT, WARN),
        ("DMZ firewall", "Inbound web permits", "destination reached", OK_SOFT, OK),
    ]
    for index, (name, line1, line2, fill, accent) in enumerate(hops):
        x = 76 + index * 262
        box(c, x, 226, 236, 120, name, [line1, line2], fill=fill, accent=accent)
        if index < 3:
            c.arrow(x + 236, 286, x + 260, 286)

    # The verdict is the largest type in the figure on purpose: the whole point of the
    # diagram is that these two words are separate answers, and they have to be the
    # thing a reader's eye lands on.
    c.rect(70, 386, 500, 162, fill=WHITE, outline=ACCENT, width=2)
    c.text(320, 416, "ROUTING", sem(TYPE["band"]), fill=ACCENT, anchor="mm")
    c.text(320, 450, "routed", bld(26), fill=OK, anchor="mm")
    c.lines(320, 486, ["traced end to end, every hop on", "a device in the inventory"],
            reg(TYPE["detail"]), fill=SUBTLE)

    c.rect(610, 386, 500, 162, fill=WHITE, outline=ACCENT, width=2)
    c.text(860, 416, "POLICY", sem(TYPE["band"]), fill=ACCENT, anchor="mm")
    c.text(860, 450, "partially-allowed", bld(26), fill=WARN, anchor="mm")
    c.lines(860, 486, ["every firewall permitted it — and one", "of them may have rewritten the addresses"],
            reg(TYPE["detail"]), fill=SUBTLE)

    c.rect(70, 576, 1040, 110, fill=WARN_SOFT, outline=WARN)
    c.band(94, 604, "WHY NOT SIMPLY “ALLOWED”", fill=WARN)
    # Re-wrapped for the larger type, and re-worded because the product changed under
    # it: NAT *is* followed across hops now, and a translation the walk can follow no
    # longer weakens the verdict at all. What still does is a translation it cannot
    # read — a pool chosen per session, an interface whose address the rule does not
    # state — which is exactly the case this estate is in.
    warning = [
        "the path continues past a device whose NAT could not be followed, so the firewalls after it",
        "were asked about the addresses in the query rather than the ones the packet was carrying.",
        "Somebody opens a firewall on this answer.",
    ]
    warning_font = reg(TYPE["note"])
    for line in warning:
        fits("figure 4 warning", line, warning_font, 1040 - 2 * PAD)
    c.lines(590, 626, warning, warning_font, fill=WARN)

    c.save("fig4_path.png")


# ───────────────────────── figure 5 — runtime topology ───────────────────────


def fig5_topology() -> None:
    c = Canvas(1180, 650, BG)
    c.title(
        "What actually runs",
        "Self-hosted, one compose stack, and outbound connections only to the "
        "devices you name",
    )

    # The left panel gives up 48px to widen the channel between the two panels. The
    # outbound arrow's labels live in that channel, and at the larger type they had
    # been running back over the worker box and across the panel border.
    c.rect(60, 100, 658, 486, fill=WHITE)
    c.band(80, 124, "YOUR INFRASTRUCTURE — ONE DOCKER COMPOSE STACK")

    box(c, 88, 148, 196, 100, "proxy", ["Caddy", "TLS, :443"], fill=ACCENT_SOFT, accent=ACCENT)
    box(c, 306, 148, 196, 100, "api", ["FastAPI", "uvicorn"])
    box(c, 524, 148, 186, 100, "db", ["PostgreSQL 16", "one volume"])
    c.arrow(284, 198, 304, 198)
    c.arrow(502, 198, 522, 198)

    # Worker last, so the outbound arrow leaves the process that actually makes the
    # connection. Nothing here calls another process; they meet in the database.
    box(c, 88, 292, 196, 100, "static", ["the built SPA"])
    box(c, 306, 292, 196, 100, "scheduler", ["fires due", "schedules"])
    box(c, 524, 292, 186, 100, "worker × N", ["collections,", "assessments"])
    c.text(399, 272, "every process meets in the database — none of them calls another",
           reg(TYPE["note"]), fill=SUBTLE, anchor="mm")

    # The note moved below the table rather than beside it. At the old sizes the
    # longest row already ended exactly where the note began; anything larger would
    # have run straight through it, and a column of monospace figures is the one thing
    # here that cannot be allowed to reflow.
    c.rect(88, 424, 622, 146, fill=PANEL)
    c.band(110, 448, "SIZING — THE SMALL TIER IS THE SAME PRODUCT")
    sizing_font = mono(TYPE["detail"] - 1)
    sizing = [
        "≤   100 devices    2 vCPU,  4 GB    1 worker",
        "≤   500 devices    4 vCPU,  8 GB    1 worker, 20 concurrent",
        "≤ 2,000 devices    8 vCPU, 16 GB    3–4 workers",
    ]
    for row in sizing:
        fits("figure 5 sizing row", row, sizing_font, 622 - 2 * 22)
    c.lines(110, 476, sizing, sizing_font, fill=SUBTLE, anchor="lm", lh=21)
    c.text(110, 546, "collections are IO-bound — scale workers before cores",
           reg(TYPE["note"]), fill=SUBTLE, anchor="lm")

    c.rect(822, 100, 298, 486, fill=WHITE)
    c.band(842, 124, "YOUR NETWORK")
    targets = [
        ("Cisco", "IOS, IOS-XE, NX-OS, ASA"),
        ("Palo Alto", "PAN-OS, Panorama"),
        ("Fortinet", "FortiOS, FortiManager"),
        ("Check Point", "Gaia, Management API"),
        ("Wireless and AAA", "WLC, ISE, FreeRADIUS"),
    ]
    name_font, detail_font = sem(TYPE["heading"] - 1), reg(TYPE["detail"])
    for index, (name, detail) in enumerate(targets):
        y = 150 + index * 84
        c.rect(846, y, 250, 70, fill=PANEL)
        fits(f"figure 5 target {name!r}", detail, detail_font, 250 - 2 * 20)
        c.text(866, y + 26, name, name_font)
        c.text(866, y + 50, detail, detail_font, fill=SUBTLE)

    # Stops at the panel edge: workers reach the whole estate, not the vendor that
    # happens to sit at this height.
    #
    # The two labels sit in the channel between the panels, which is the one place on
    # this figure where text has nothing to clip against — so the width is asserted
    # rather than assumed. They overran both neighbours at the first larger size, and
    # nothing in the figure showed it except the picture.
    channel = 822 - 718
    arrow_font = mono(TYPE["detail"] - 2)
    for label in ("tcp/22 · 443", "read only"):
        fits("figure 5 channel label", label, arrow_font, channel)
    c.arrow(722, 342, 818, 342, colour=OK, width=2.2)
    c.text(770, 318, "tcp/22 · 443", arrow_font, fill=OK, anchor="mm")
    c.text(770, 366, "read only", arrow_font, fill=OK, anchor="mm")

    c.save("fig5_topology.png")


def main() -> None:
    print("rendering:")
    fig1_architecture()
    fig2_readonly()
    fig3_pipeline()
    fig4_path()
    fig5_topology()

    # Checked after the figures are written, not instead of writing them: seeing the
    # broken output is most of how an overflow gets fixed. The non-zero exit is what
    # stops it being committed.
    if _OVERFLOWS:
        print(f"\n{len(_OVERFLOWS)} text overflow(s) — the figures above are wrong:\n")
        for problem in _OVERFLOWS:
            print(f"  {problem}")
        print(
            "\nEither shorten the string, widen the box, or lower the size in TYPE. "
            "Do not leave it: the text is outside its own border."
        )
        raise SystemExit(1)

    print(f"\nwritten to {OUT}")


if __name__ == "__main__":
    main()
