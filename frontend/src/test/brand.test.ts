/** Guards on the generated brand assets.
 *
 * `tools/build_brand_assets.py` derives everything under `public/brand/` from the master
 * artwork in `docs/brand/`. Both the script's output and this stylesheet's
 * `--brand-field` are committed, and the two have to stay in step — so this reads the
 * actual pixels rather than trusting a comment.
 *
 * Two properties are checked, and each has already been got wrong once:
 *
 * 1. **The field matches the token.** The logo ships with its own opaque near-white
 *    background instead of a transparent one (keying it out clamps every stroke lighter
 *    than the field to nothing — the pale traces, the white glyphs in the shield badges,
 *    the connector lines). Every surface showing it therefore paints `--brand-field`
 *    behind it, and if the artwork is re-exported on a different white, or the token is
 *    "tidied" to `#ffffff`, the result is a one-value seam: invisible on a good monitor,
 *    obvious on a cheap one.
 *
 * 2. **The mark is the shield alone.** It renders at 26px in the sidebar and in the
 *    favicon, where the wordmark is indistinguishable from dirt. The first two builds
 *    both leaked it in — once because the crop took its width from the wordmark's
 *    flanking rules, once because the margin and the squaring each reached below the
 *    shield/wordmark boundary. Neither was visible in the asset's *dimensions*, which
 *    are forced to 256x256 regardless, so this measures ink placement instead.
 */

import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { inflateSync } from 'node:zlib';

import { describe, expect, it } from 'vitest';

const PNG_SIGNATURE = '89504e470d0a1a0a';

/** The master's background, sampled not assumed. Must equal `--brand-field`. */
const FIELD: readonly [number, number, number] = [254, 254, 254];

/** How far off the field a pixel counts as ink — matches TOLERANCE in the build script. */
const TOLERANCE = 6;

// Resolved from vitest's root rather than `import.meta.url`: under the jsdom environment
// modules are transformed and `import.meta.url` is an http URL, which `fileURLToPath`
// rejects. The guard stops a wrong working directory becoming a confusing failure later.
const ROOT = process.cwd();
if (!existsSync(resolve(ROOT, 'vite.config.ts'))) {
  throw new Error(`Expected to run from the frontend project root; got ${ROOT}`);
}

const asset = (name: string) => resolve(ROOT, 'public', name);
const LOCKUP = 'brand/netsecops-lockup.png';
const MARK = 'brand/netsecops-mark.png';

interface Png {
  width: number;
  height: number;
  /** True if (x, y) is background. */
  isField(x: number, y: number): boolean;
  /** `#rrggbb` at (x, y). */
  hex(x: number, y: number): string;
}

/** A byte, with out-of-range reading as zero.
 *
 * That is not a shrug at `noUncheckedIndexedAccess`: it is what the PNG specification
 * says. Reconstructing a filtered byte refers to its left, upper and upper-left
 * neighbours, and all three are defined as zero where they fall outside the image, which
 * is precisely the top row and the left edge. The inflated length is asserted separately
 * so this can never quietly paper over a truncated file.
 */
const byte = (buffer: Uint8Array, index: number): number => buffer[index] ?? 0;

function paeth(a: number, b: number, c: number): number {
  const p = a + b - c;
  const pa = Math.abs(p - a);
  const pb = Math.abs(p - b);
  const pc = Math.abs(p - c);
  if (pa <= pb && pa <= pc) return a;
  return pb <= pc ? b : c;
}

/** Decode an 8-bit truecolour, non-interlaced PNG.
 *
 * Deliberately no image library: adding one to the frontend's dev dependencies to
 * inspect two committed files costs more than the un-filtering loop below, which is the
 * whole of the PNG specification that still applies once palette, alpha and Adam7 are
 * ruled out. The header fields are asserted rather than assumed for exactly that reason
 * — a re-export as palette or interlaced would otherwise be misread as plausible-looking
 * wrong colours instead of failing.
 */
function readPng(path: string): Png {
  const png = readFileSync(path);
  expect(png.subarray(0, 8).toString('hex'), `${path} is not a PNG`).toBe(PNG_SIGNATURE);

  let header: Buffer | undefined;
  const chunks: Buffer[] = [];

  for (let offset = 8; offset + 8 <= png.length;) {
    const length = png.readUInt32BE(offset);
    const type = png.subarray(offset + 4, offset + 8).toString('ascii');
    if (type === 'IHDR') header = png.subarray(offset + 8, offset + 8 + length);
    if (type === 'IDAT') chunks.push(png.subarray(offset + 8, offset + 8 + length));
    if (type === 'IEND') break;
    offset += length + 12; // length + type + data + CRC
  }

  if (!header || chunks.length === 0) throw new Error(`${path} has no IHDR/IDAT - truncated?`);

  expect(header.readUInt8(8), `${path}: expected 8-bit samples`).toBe(8);
  expect(header.readUInt8(9), `${path}: expected truecolour RGB, no palette or alpha`).toBe(2);
  expect(header.readUInt8(12), `${path}: expected no interlacing`).toBe(0);

  const width = header.readUInt32BE(0);
  const height = header.readUInt32BE(4);
  const bpp = 3;
  const stride = width * bpp;

  const raw = inflateSync(Buffer.concat(chunks));
  expect(raw.length, `${path}: inflated size does not match the header`).toBe(
    height * (stride + 1),
  );

  const out = new Uint8Array(stride * height);

  for (let y = 0; y < height; y += 1) {
    const filter = byte(raw, y * (stride + 1));
    const line = y * (stride + 1) + 1;
    for (let i = 0; i < stride; i += 1) {
      const x = byte(raw, line + i);
      const a = i >= bpp ? byte(out, y * stride + i - bpp) : 0; // left
      const b = y > 0 ? byte(out, (y - 1) * stride + i) : 0; // above
      const c = i >= bpp && y > 0 ? byte(out, (y - 1) * stride + i - bpp) : 0; // upper-left
      let value: number;
      switch (filter) {
        case 0:
          value = x;
          break;
        case 1:
          value = x + a;
          break;
        case 2:
          value = x + b;
          break;
        case 3:
          value = x + ((a + b) >> 1);
          break;
        case 4:
          value = x + paeth(a, b, c);
          break;
        default:
          throw new Error(`${path}: unknown filter type ${filter} on row ${y}`);
      }
      out[y * stride + i] = value & 0xff;
    }
  }

  const at = (x: number, y: number) => y * stride + x * bpp;

  return {
    width,
    height,
    isField: (x, y) =>
      FIELD.every((channel, index) => Math.abs(byte(out, at(x, y) + index) - channel) <= TOLERANCE),
    hex: (x, y) =>
      `#${[0, 1, 2]
        .map((i) =>
          byte(out, at(x, y) + i)
            .toString(16)
            .padStart(2, '0'),
        )
        .join('')}`,
  };
}

/** Height-to-width ratio of the image's ink, ignoring the surrounding field. */
function inkAspect(png: Png): number {
  let left = png.width;
  let right = -1;
  let top = png.height;
  let bottom = -1;

  for (let y = 0; y < png.height; y += 1) {
    for (let x = 0; x < png.width; x += 1) {
      if (png.isField(x, y)) continue;
      if (x < left) left = x;
      if (x > right) right = x;
      if (y < top) top = y;
      if (y > bottom) bottom = y;
    }
  }

  if (right < 0) throw new Error('image is entirely background');
  return (bottom - top + 1) / (right - left + 1);
}

/** Fraction of the image that is ink rather than background. */
function inkCoverage(png: Png): number {
  let ink = 0;
  for (let y = 0; y < png.height; y += 1) {
    for (let x = 0; x < png.width; x += 1) {
      if (!png.isField(x, y)) ink += 1;
    }
  }
  return ink / (png.width * png.height);
}

/** Ink pixels inside a square block with its top-left at (x0, y0). */
function inkIn(png: Png, x0: number, y0: number, size: number): number {
  let count = 0;
  for (let y = y0; y < y0 + size; y += 1) {
    for (let x = x0; x < x0 + size; x += 1) {
      if (!png.isField(x, y)) count += 1;
    }
  }
  return count;
}

function brandField(css: string): string {
  const value = /--brand-field:\s*(#[0-9a-f]{3,8})/i.exec(css)?.[1];
  if (!value) throw new Error('--brand-field is not defined in the stylesheet');
  return value.toLowerCase();
}

describe('brand assets', () => {
  const css = readFileSync(resolve(ROOT, 'src/styles/index.css'), 'utf8');

  it.each([LOCKUP, MARK])('%s has a field matching --brand-field', (name) => {
    expect(readPng(asset(name)).hex(0, 0)).toBe(brandField(css));
  });

  it('defines --brand-field exactly once', () => {
    // Not a theme colour: it is the artwork's own background. Redefining it in the dark
    // block would put a different card behind the logo per theme, with a seam on at
    // least one of them.
    expect(css.match(/--brand-field:/g)).toHaveLength(1);
  });

  it('crops the mark to the shield, with no wordmark bleeding in', () => {
    const mark = readPng(asset(MARK));
    const block = Math.round(mark.width * 0.15);

    // A shield tapers to a point, so its bottom corners are empty field. Wordmark caps
    // are not: the two builds that got this wrong put 91 and 137 ink pixels in the
    // bottom-left block, against zero when the crop is right.
    expect(inkIn(mark, 0, mark.height - block, block)).toBe(0);
    expect(inkIn(mark, mark.width - block, mark.height - block, block)).toBe(0);

    // And the shield is taller than it is wide. This is the ovalisation check: the file
    // is always 256x256, so only the ink's proportions can show that a non-square crop
    // was squashed into a square canvas (1.21 when correct, 0.97 when not).
    expect(inkAspect(mark)).toBeGreaterThan(1.15);
  });

  it('keeps the lockup a separate, wider asset', () => {
    // The two exist for different jobs, and the failure mode is one collapsing into the
    // other. The lockup carries the wordmark and its flanking rules, so its ink is wider
    // than tall — the opposite of the mark's.
    expect(inkAspect(readPng(asset(LOCKUP)))).toBeLessThan(1);
  });

  it.each([LOCKUP, MARK])('%s decodes to artwork rather than noise', (name) => {
    // A decoder bug does not have to make the image unreadable to make the checks above
    // lie. Reconstructing Paeth-filtered rows as Up leaves flat regions exactly right —
    // so the corner pixel and the empty bottom blocks still pass — while corrupting
    // everything with a gradient, which is most of the logo. It shows up in ink
    // coverage: about a fifth of each asset when decoded correctly, a third when not.
    //
    // The band is deliberately wide. This is a sanity check on the decoder, not a pixel
    // snapshot of the logo, and a redrawn logo should not fail it.
    const coverage = inkCoverage(readPng(asset(name)));
    expect(coverage).toBeGreaterThan(0.1);
    expect(coverage).toBeLessThan(0.28);
  });

  it('ships every asset the markup references', () => {
    const markup = ['index.html', 'src/features/auth/LoginPage.tsx', 'src/components/AppLayout.tsx']
      .map((file) => readFileSync(resolve(ROOT, file), 'utf8'))
      .join('\n');

    const referenced = [...markup.matchAll(/["'](\/(?:brand\/[\w.-]+|favicon\.ico))["']/g)].flatMap(
      (match) => (match[1] ? [match[1]] : []),
    );

    // A missing brand file is a 404 that renders as a broken-image glyph on the sign-in
    // screen. Nothing in the build fails, so nothing catches it before a user does.
    expect(referenced.length).toBeGreaterThan(0);
    for (const path of new Set(referenced)) {
      expect(existsSync(asset(path.slice(1))), `${path} is referenced but missing`).toBe(true);
    }
  });
});
