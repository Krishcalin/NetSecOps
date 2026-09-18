"""Derive the console's brand assets from the master artwork.

    pip install pillow && python tools/build_brand_assets.py

Pillow is not in `backend/pyproject.toml` and should not be: this runs by hand on the
rare occasion the logo changes, its outputs are committed, and CI never invokes it — so
adding an image library to the application's dependency tree (and to its SBOM and CVE
surface) would buy nothing. `frontend/src/test/brand.test.ts` checks the committed
results on every run without it.

Source of truth is ``docs/brand/netsecops-master.png`` — the supplied logo, committed
unmodified. Everything the application serves is generated from it by this script and
committed alongside, so the derivation is reviewable and repeatable rather than a
one-off crop somebody did once and cannot reproduce.

**Two assets, not one.** A lockup for the sign-in panel, and a square shield-only mark
for the ~26px header and the favicon. Cropping the lockup square would drag the wordmark
and the orange rules into a 16px icon, where they are indistinguishable from dirt.

**The field is kept, never keyed out.** The obvious move is to make the near-white
background transparent so the logo sits on any surface. Do not: un-mixing projects each
pixel toward the target ink, so every stroke lighter than the field clamps to nothing —
the pale blue traces, the white glyphs inside the shield badges, the thin connector
lines. All of those are load-bearing here. The asset keeps its field and the console
paints the panel behind it the same value, which is why :data:`FIELD` is exported into
the stylesheet as ``--brand-field`` and asserted by a test.

That matters more than usual because the console has a dark theme. On ``--bg: #101317``
a white-field logo with no panel reads as a rendering fault; with one it reads as a
deliberate white card, which is how the logo is meant to be seen.
"""

from __future__ import annotations

import pathlib
import sys

from PIL import Image

ROOT = pathlib.Path(__file__).resolve().parent.parent
MASTER = ROOT / "docs" / "brand" / "netsecops-master.png"
OUT = ROOT / "frontend" / "public" / "brand"

#: The master's own background value, sampled rather than assumed.
#:
#: It is #fefefe, not #ffffff. A panel painted pure white leaves a one-value seam around
#: the asset that is invisible on a good monitor and obvious on a cheap one.
FIELD = (254, 254, 254)

#: How close a pixel must be to the field to count as background when trimming.
TOLERANCE = 6

#: Widths the console actually renders at, doubled for high-density displays.
LOCKUP_WIDTH = 560
MARK_SIZE = 256
FAVICON_SIZES = (16, 32, 48)

#: Padding left around the trimmed content, as a fraction of the shorter side. Trimming
#: to the exact ink makes the logo touch the panel edge, which reads as a crop rather
#: than as a logo.
MARGIN = 0.06


def is_field(pixel: tuple[int, int, int]) -> bool:
    return all(abs(a - b) <= TOLERANCE for a, b in zip(pixel, FIELD, strict=True))


def content_box(
    image: Image.Image, *, rows_between: tuple[int, int] | None = None
) -> tuple[int, int, int, int]:
    """The bounding box of everything that is not background.

    ``rows_between`` restricts the scan to a horizontal band, which the shield crop needs
    and which is easy to get wrong: the full artwork's width is set by the orange rules
    flanking the wordmark, and they are wider than the shield. Squaring a box built from
    that width forces it taller than the shield, which pulls the wordmark back into what
    is meant to be a shield-only mark — the first version of this script did exactly
    that, and the 256px "mark" came out as a slightly cropped copy of the lockup.
    """
    width, height = image.size
    pixels = image.load()
    first, last = rows_between or (0, height)

    def row_has_ink(y: int) -> bool:
        return any(not is_field(pixels[x, y]) for x in range(width))

    def column_has_ink(x: int) -> bool:
        return any(not is_field(pixels[x, y]) for y in range(first, last))

    rows = [y for y in range(first, last) if row_has_ink(y)]
    columns = [x for x in range(width) if column_has_ink(x)]
    if not rows or not columns:
        raise SystemExit("The master artwork appears to be blank.")
    return columns[0], rows[0], columns[-1] + 1, rows[-1] + 1


def shield_bottom(image: Image.Image, box: tuple[int, int, int, int]) -> int:
    """The row where the shield ends and the wordmark begins.

    Found by ink density rather than by a hardcoded fraction: the two blocks nearly
    touch — the shield's point sits just above the wordmark's cap height — so there is no
    empty row to split on, but there is a clear trough. Measuring it means the script
    still works if the artwork is re-exported at another size or with different spacing.
    """
    left, top, right, bottom = box
    pixels = image.load()

    density = [
        (y, sum(0 if is_field(pixels[x, y]) else 1 for x in range(left, right)))
        for y in range(top, bottom)
    ]

    # Search the middle half only. The trough is between the two blocks; the emptier
    # margins above and below would otherwise win.
    lower, upper = top + (bottom - top) // 2, top + (bottom - top) * 9 // 10
    candidates = [(count, y) for y, count in density if lower <= y <= upper]
    if not candidates:
        raise SystemExit("Could not locate the shield/wordmark boundary.")
    return min(candidates)[1]


def pad(box: tuple[int, int, int, int], size: tuple[int, int]) -> tuple[int, int, int, int]:
    left, top, right, bottom = box
    margin = int(min(right - left, bottom - top) * MARGIN)
    return (
        max(0, left - margin),
        max(0, top - margin),
        min(size[0], right + margin),
        min(size[1], bottom + margin),
    )


def squared(
    box: tuple[int, int, int, int], size: tuple[int, int], *, floor: int | None = None
) -> tuple[int, int, int, int]:
    """Expand a box to a square about its own centre, clamped to the image.

    Squared before resizing rather than after: scaling a non-square crop into a square
    canvas is how a shield ends up subtly ovalised, which nobody reports and everybody
    notices.

    ``floor`` is a row the box may not extend past, and it exists because both padding
    and squaring quietly reach downward. The shield is taller than it is wide, so
    squaring widens it — but the 6% margin added first pushed the bottom edge below the
    measured shield/wordmark boundary, and the "shield-only" mark came out with the caps
    of `NetSecOps` sliced across its foot. Clamping is done by *shifting* the square up,
    never by shrinking it, so the result stays square.
    """
    left, top, right, bottom = box
    side = max(right - left, bottom - top)
    cx, cy = (left + right) // 2, (top + bottom) // 2
    half = side // 2

    left, right = cx - half, cx + half
    top, bottom = cy - half, cy + half

    if floor is not None and bottom > floor:
        shift = bottom - floor
        top, bottom = top - shift, bottom - shift

    # Clamp by shifting rather than shrinking, so the result stays square.
    if left < 0:
        left, right = 0, side
    if top < 0:
        top, bottom = 0, side
    if right > size[0]:
        left, right = size[0] - side, size[0]
    if bottom > size[1]:
        top, bottom = size[1] - side, size[1]
    return left, top, right, bottom


def save(image: Image.Image, path: pathlib.Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    image.save(path, optimize=True)
    print(f"  {path.relative_to(ROOT).as_posix():48s} {image.size[0]}x{image.size[1]}")


def main() -> int:
    if not MASTER.exists():
        print(f"Master artwork not found: {MASTER}", file=sys.stderr)
        return 1

    master = Image.open(MASTER).convert("RGB")
    sampled = master.getpixel((0, 0))
    if not is_field(sampled):  # type: ignore[arg-type]
        print(
            f"The master's corner pixel is {sampled}, not the expected field {FIELD}. "
            "Update FIELD and --brand-field together, or the panel will show a seam.",
            file=sys.stderr,
        )
        return 1

    box = content_box(master)
    split = shield_bottom(master, box)
    print(f"master {master.size[0]}x{master.size[1]}  content {box}  shield ends y={split}")

    # ── the lockup: everything, for the sign-in panel ───────────────────
    lockup = master.crop(pad(box, master.size))
    height = round(lockup.size[1] * LOCKUP_WIDTH / lockup.size[0])
    save(lockup.resize((LOCKUP_WIDTH, height), Image.LANCZOS), OUT / "netsecops-lockup.png")

    # ── the mark: shield only, square, for the header and favicon ───────
    # Re-measured within the shield's own band, so its width comes from the shield and
    # not from the wordmark's flanking rules.
    shield_box = content_box(master, rows_between=(box[1], split))
    shield = squared(pad(shield_box, master.size), master.size, floor=split)
    mark = master.crop(shield).resize((MARK_SIZE, MARK_SIZE), Image.LANCZOS)
    save(mark, OUT / "netsecops-mark.png")

    # A real multi-size .ico: the browser tab, the bookmark bar and the Windows taskbar
    # all ask for different sizes, and letting one of them downscale a 256px image gives
    # a muddy 16px that a purpose-built one does not.
    favicon = OUT.parent / "favicon.ico"
    mark.save(favicon, sizes=[(size, size) for size in FAVICON_SIZES])
    print(f"  {favicon.relative_to(ROOT).as_posix():48s} {list(FAVICON_SIZES)}")

    print(f"\nField is #{FIELD[0]:02x}{FIELD[1]:02x}{FIELD[2]:02x} — keep --brand-field in step.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
