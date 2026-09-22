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
        self.text(self.w / 2, 34, text, bld(19), anchor="mm")
        if subtitle:
            self.text(self.w / 2, 60, subtitle, reg(12.5), fill=SUBTLE, anchor="mm")

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
    """A labelled panel: bold heading, muted detail lines beneath."""
    c.rect(x, y, w, h, fill=fill, outline=outline)
    if accent:
        c.rect(x, y, 4.5, h, fill=accent, outline=None, radius=2)
    c.text(x + w / 2, y + 21, heading, sem(13), anchor="mm")
    if rows:
        c.lines(x + w / 2, y + 42, rows, reg(10.8), fill=SUBTLE)


# ─────────────────────── figure 1 — logical architecture ─────────────────────


def fig1_architecture() -> None:
    c = Canvas(1180, 660, BG)
    c.title(
        "Logical architecture",
        "One origin, one control plane, and a worker pool that is the only thing "
        "that ever reaches a device",
    )

    c.rect(60, 92, 1060, 150, fill=WHITE)
    c.text(78, 112, "BROWSER AND EDGE", sem(10.5), fill=SUBTLE)
    box(c, 90, 130, 210, 92, "React console", ["Vite + TypeScript", "cookie session"],
        fill=ACCENT_SOFT, accent=ACCENT)
    box(c, 350, 130, 210, 92, "Caddy", ["TLS, security headers", "SPA + /api on one origin"])
    box(c, 610, 130, 210, 92, "FastAPI", ["RBAC, CSRF, audit", "OpenAPI at /api/v1"])
    box(c, 870, 130, 210, 92, "PostgreSQL 16", ["JSONB, INET, ltree", "Alembic migrations"])
    c.arrow(300, 176, 348, 176)
    c.arrow(560, 176, 608, 176)
    c.arrow(820, 176, 868, 176)

    c.rect(60, 268, 1060, 168, fill=WHITE)
    c.text(78, 288, "SERVICES — BUSINESS LOGIC, INDEPENDENT OF HTTP", sem(10.5), fill=SUBTLE)
    services = [
        ("Inventory", ["devices, groups", "sites, tags"]),
        ("Credentials", ["AES-256-GCM vault", "never returned"]),
        ("Assessment", ["104 checks", "findings, risk"]),
        ("Vulnerability", ["CVE, KEV, EPSS", "end-of-life"]),
        ("Topology", ["layer-3 graph", "path analysis"]),
    ]
    for index, (name, rows) in enumerate(services):
        box(c, 90 + index * 205, 306, 185, 112, name, rows)

    c.text(590, 452, "services enqueue jobs and workers claim them — no worker ever serves HTTP",
           reg(10.8), fill=SUBTLE, anchor="mm")

    c.rect(60, 472, 1060, 160, fill=WHITE)
    c.text(78, 492, "WORKERS AND ADAPTERS — THE ONLY PATH TO A DEVICE", sem(10.5), fill=SUBTLE)
    box(c, 90, 510, 230, 104, "Job runner", ["claims work with", "FOR UPDATE SKIP LOCKED"])
    box(c, 370, 510, 230, 104, "Read-only guard", ["allow-list, deny-list", "see figure 2"],
        fill=OK_SOFT, accent=OK)
    box(c, 650, 510, 200, 104, "Adapters", ["SSH and vendor", "HTTPS APIs"])
    box(c, 900, 510, 180, 104, "Devices", ["13 platforms", "never written to"],
        fill=PANEL)
    c.arrow(320, 562, 368, 562)
    c.arrow(600, 562, 648, 562)
    c.arrow(850, 562, 898, 562)

    # Into the gap between Assessment and Vulnerability, so it points at the band rather
    # than appearing to single out one service.
    c.arrow(697, 242, 697, 300, dashed=True)

    c.save("fig1_architecture.png")


# ────────────────────── figure 2 — the read-only guarantee ───────────────────


def fig2_readonly() -> None:
    c = Canvas(1180, 620, BG)
    c.title(
        "The read-only guarantee",
        "Four layers, every one of them before transmission — nothing is filtered "
        "after the fact",
    )

    c.rect(60, 92, 1060, 300, fill=WHITE)

    box(c, 96, 128, 188, 118, "1 · Allow-list", ["every adapter declares", "exactly what it may send"],
        fill=OK_SOFT, accent=OK)
    box(c, 318, 128, 188, 118, "2 · Deny-list", ["write verbs blocked even", "if an entry were wrong"],
        fill=OK_SOFT, accent=OK)
    box(c, 540, 128, 188, 118, "3 · GET-only REST", ["POST only for auth and", "POST-only vendor APIs"],
        fill=OK_SOFT, accent=OK)
    box(c, 762, 128, 188, 118, "4 · Guarded session", ["adapters hold no", "unchecked transport"],
        fill=OK_SOFT, accent=OK)

    for x in (284, 506, 728):
        c.arrow(x, 187, x + 32, 187, colour=OK)

    box(c, 984, 128, 120, 118, "Device", ["read", "only"], fill=PANEL)
    c.arrow(950, 187, 982, 187, colour=OK)

    c.rect(96, 278, 854, 92, fill=ERROR_SOFT, outline=ERROR)
    c.text(120, 304, "REJECTED BEFORE TRANSMISSION", sem(12), fill=ERROR)
    c.lines(
        523,
        332,
        [
            "configure · write · copy · reload · commit · delete · ping · test aaa · debug",
            "anything an adapter did not declare, and anything with a side effect on the device",
        ],
        reg(10.8),
        fill=ERROR,
    )
    c.arrow(523, 278, 523, 250, colour=ERROR)

    c.rect(60, 418, 1060, 160, fill=WHITE)
    c.text(78, 440, "HOW THE CLAIM IS CHECKED", sem(10.5), fill=SUBTLE)
    box(c, 96, 458, 300, 100, "283 conformance assertions",
        ["what the guard decides", "the build fails on any"])
    box(c, 430, 458, 300, 100, "A fake SSH device",
        ["records every byte received", "checks what actually arrives"])
    box(c, 764, 458, 320, 100, "A tamper-evident audit log",
        ["every command, hash-chained", "so a customer can read it back"])

    c.save("fig2_readonly.png")


# ───────────────────────── figure 3 — assessment pipeline ────────────────────


def fig3_pipeline() -> None:
    c = Canvas(1180, 640, BG)
    c.title(
        "From a device to a finding",
        "Everything reads one normalised model, so a check written once runs on "
        "thirteen platforms",
    )

    box(c, 70, 110, 180, 96, "Collect", ["read-only commands", "and vendor API reads"])
    box(c, 290, 110, 180, 96, "Store", ["sealed artefact", "redacted snapshot"])
    box(c, 510, 110, 180, 96, "Parse", ["one parser", "per platform"])
    c.arrow(250, 158, 288, 158)
    c.arrow(470, 158, 508, 158)
    c.arrow(690, 158, 742, 158)

    c.rect(742, 96, 368, 124, fill=ACCENT_SOFT, outline=ACCENT, width=2.2)
    c.text(926, 124, "Normalised Config Model", bld(15), anchor="mm")
    c.lines(
        926,
        152,
        [
            "vendor-neutral: interfaces, routes, AAA, crypto,",
            "firewall rules, NAT, users, logging, versions",
        ],
        reg(11),
        fill=SUBTLE,
    )

    # A bus rather than a fan: four splayed diagonals cross whatever caption sits under
    # them, and the point is that every engine reads the *same* thing.
    centres = [197.5, 459.5, 721.5, 983.5]
    c.d.line([926 * S, 220 * S, 926 * S, 256 * S], fill=SUBTLE, width=max(1, int(1.8 * S)))
    c.d.line(
        [centres[0] * S, 256 * S, centres[-1] * S, 256 * S],
        fill=SUBTLE,
        width=max(1, int(1.8 * S)),
    )
    for x in centres:
        c.arrow(x, 256, x, 298)

    c.text(80, 240, "every engine reads the same model — none of them parses anything",
           reg(10.8), fill=SUBTLE, anchor="lm")

    engines = [
        ("Check engine", ["104 checks, JMESPath", "pass / fail / not evaluated"], ACCENT),
        ("Firewall analysis", ["shadowed, redundant,", "unused, any-any"], ACCENT),
        ("Vulnerability", ["CPE, CVE, KEV, EPSS", "end-of-life"], ACCENT),
        ("Topology", ["layer-3 graph", "path analysis"], ACCENT),
    ]
    for index, (name, rows, accent) in enumerate(engines):
        box(c, 80 + index * 262, 300, 235, 112, name, rows, accent=accent)

    c.rect(70, 452, 1040, 150, fill=WHITE)
    c.text(88, 474, "WHAT COMES OUT", sem(10.5), fill=SUBTLE)
    box(c, 100, 492, 220, 96, "Findings", ["with a lifecycle,", "evidence and remediation"],
        fill=WARN_SOFT, accent=WARN)
    box(c, 350, 492, 220, 96, "Risk score", ["per device, with its", "components shown"])
    box(c, 600, 492, 220, 96, "Compliance", ["CIS, NIST, PCI, ISO", "pivoted by control"])
    box(c, 850, 492, 240, 96, "Reports", ["frozen at generation,", "dated artefacts"])
    for x in (210, 460, 710, 970):
        c.arrow(x, 418, x, 490)

    c.save("fig3_pipeline.png")


# ───────────────────────── figure 4 — the two axes ───────────────────────────


def fig4_path() -> None:
    c = Canvas(1180, 660, BG)
    c.title(
        "A path answer has two axes",
        "Routing and policy fail independently, so a single verdict has to lie "
        "about one of them",
    )

    c.text(90, 112, "THE QUESTION", sem(10.5), fill=SUBTLE)
    c.rect(70, 126, 1040, 54, fill=WHITE)
    c.text(590, 153, "can 10.10.10.50 reach 10.20.0.10 on tcp/443, and what decides?",
           mono(13), anchor="mm")

    hops = [
        ("access switch", "no rulebase", "no decision", PANEL, SUBTLE),
        ("core switch", "no rulebase", "no decision", PANEL, SUBTLE),
        ("edge firewall", "INSIDE-IN permits", "and it translates", WARN_SOFT, WARN),
        ("DMZ firewall", "Inbound web permits", "destination reached", OK_SOFT, OK),
    ]
    for index, (name, line1, line2, fill, accent) in enumerate(hops):
        x = 78 + index * 262
        box(c, x, 214, 232, 112, name, [line1, line2], fill=fill, accent=accent)
        if index < 3:
            c.arrow(x + 232, 270, x + 260, 270)

    c.rect(70, 362, 500, 150, fill=WHITE, outline=ACCENT, width=2)
    c.text(320, 390, "ROUTING", sem(12), fill=ACCENT, anchor="mm")
    c.text(320, 420, "routed", bld(22), fill=OK, anchor="mm")
    c.lines(320, 452, ["traced end to end, every hop on", "a device in the inventory"],
            reg(11), fill=SUBTLE)

    c.rect(610, 362, 500, 150, fill=WHITE, outline=ACCENT, width=2)
    c.text(860, 390, "POLICY", sem(12), fill=ACCENT, anchor="mm")
    c.text(860, 420, "partially-allowed", bld(22), fill=WARN, anchor="mm")
    c.lines(860, 452, ["every firewall permitted it — and one", "of them may have rewritten the addresses"],
            reg(11), fill=SUBTLE)

    c.rect(70, 540, 1040, 84, fill=WARN_SOFT, outline=WARN)
    c.text(94, 566, "WHY NOT SIMPLY “ALLOWED”", sem(11), fill=WARN)
    c.lines(
        590,
        594,
        [
            "the path continues past a device carrying NAT rules, so the firewalls after it were asked about the",
            "addresses in the query rather than the ones the packet was carrying. Somebody opens a firewall on this answer.",
        ],
        reg(10.8),
        fill=WARN,
    )

    c.save("fig4_path.png")


# ───────────────────────── figure 5 — runtime topology ───────────────────────


def fig5_topology() -> None:
    c = Canvas(1180, 600, BG)
    c.title(
        "What actually runs",
        "Self-hosted, one compose stack, and outbound connections only to the "
        "devices you name",
    )

    c.rect(60, 96, 700, 430, fill=WHITE)
    c.text(80, 118, "YOUR INFRASTRUCTURE — ONE DOCKER COMPOSE STACK", sem(10.5), fill=SUBTLE)

    box(c, 92, 142, 190, 92, "proxy", ["Caddy", "TLS, :443"], fill=ACCENT_SOFT, accent=ACCENT)
    box(c, 312, 142, 190, 92, "api", ["FastAPI", "uvicorn"])
    box(c, 532, 142, 196, 92, "db", ["PostgreSQL 16", "one volume"])
    c.arrow(282, 188, 310, 188)
    c.arrow(502, 188, 530, 188)

    # Worker last, so the outbound arrow leaves the process that actually makes the
    # connection. Nothing here calls another process; they meet in the database.
    box(c, 92, 268, 190, 92, "static", ["the built SPA"])
    box(c, 312, 268, 190, 92, "scheduler", ["fires due", "schedules"])
    box(c, 532, 268, 196, 92, "worker × N", ["collections,", "assessments"])
    c.text(410, 252, "every process meets in the database — none of them calls another",
           reg(10.5), fill=SUBTLE, anchor="mm")

    c.rect(92, 394, 636, 108, fill=PANEL)
    c.text(112, 416, "SIZING — THE SMALL TIER IS THE SAME PRODUCT", sem(10.5), fill=SUBTLE)
    c.lines(
        116,
        440,
        [
            "≤   100 devices    2 vCPU,  4 GB    1 worker",
            "≤   500 devices    4 vCPU,  8 GB    1 worker, 20 concurrent",
            "≤ 2,000 devices    8 vCPU, 16 GB    3–4 workers",
        ],
        mono(10),
        fill=SUBTLE,
        anchor="lm",
        lh=16,
    )
    c.lines(
        470,
        452,
        ["collections are IO-bound —", "scale workers before cores"],
        reg(9.8),
        fill=SUBTLE,
        anchor="lm",
        lh=16,
    )

    c.rect(800, 96, 320, 430, fill=WHITE)
    c.text(820, 118, "YOUR NETWORK", sem(10.5), fill=SUBTLE)
    targets = [
        ("Cisco", "IOS, IOS-XE, NX-OS, ASA"),
        ("Palo Alto", "PAN-OS, Panorama"),
        ("Fortinet", "FortiOS, FortiManager"),
        ("Check Point", "Gaia, Management API"),
        ("Wireless and AAA", "WLC, ISE, FreeRADIUS"),
    ]
    for index, (name, detail) in enumerate(targets):
        y = 142 + index * 74
        c.rect(824, y, 272, 60, fill=PANEL)
        c.text(848, y + 22, name, sem(11.5))
        c.text(848, y + 42, detail, reg(10), fill=SUBTLE)

    # Stops at the panel edge: workers reach the whole estate, not the vendor that
    # happens to sit at this height.
    c.arrow(728, 314, 796, 314, colour=OK, width=2.2)
    c.text(762, 294, "tcp/22, tcp/443", mono(9.5), fill=OK, anchor="mm")
    c.text(762, 336, "read only", mono(9.5), fill=OK, anchor="mm")

    c.save("fig5_topology.png")


def main() -> None:
    print("rendering:")
    fig1_architecture()
    fig2_readonly()
    fig3_pipeline()
    fig4_path()
    fig5_topology()
    print(f"\nwritten to {OUT}")


if __name__ == "__main__":
    main()
