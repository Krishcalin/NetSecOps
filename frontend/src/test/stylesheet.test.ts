/** Properties of the stylesheet that cannot be seen by reading it.
 *
 * This file exists because of a bug that sat in `index.css` unnoticed: a comment lost
 * its opening `/*`, so four lines of English prose were being parsed as CSS. esbuild
 * recovered and the build went green, the page looked fine, and the only trace was a
 * warning nobody was reading. A stricter parser — or a rule that happened to follow —
 * would have taken the whole block with it.
 *
 * The rules below are all of that shape: things a browser tolerates silently and a
 * reader cannot spot.
 */

import { readFileSync } from 'fs';

import { describe, expect, it } from 'vitest';

const CSS = readFileSync('src/styles/index.css', 'utf8');

/** Strip comments the way a parser does, so the checks below look at real CSS. */
const WITHOUT_COMMENTS = CSS.replace(/\/\*[\s\S]*?\*\//g, '');

describe('the stylesheet', () => {
  it('has balanced comment delimiters', () => {
    // The bug: `*/` outnumbered `/*`, so everything between the stray close and the
    // next open was live CSS.
    const opens = (CSS.match(/\/\*/g) ?? []).length;
    const closes = (CSS.match(/\*\//g) ?? []).length;

    expect(opens).toBe(closes);
  });

  it('has no prose left outside a comment', () => {
    // What the unbalanced delimiters produced. A line of English in CSS position
    // parses as a selector and swallows the rule after it.
    const stray = WITHOUT_COMMENTS.split('\n')
      .map((line, index) => [index + 1, line.trim()] as const)
      .filter(([, line]) => /^[A-Z][a-z]+\s+[a-z]+\s+[a-z]+/.test(line) && !line.includes('{'));

    expect(stray).toEqual([]);
  });

  it('defines every section colour in both themes', () => {
    // A missing token falls back to `--border`, which renders as a grey hairline and
    // reads as a deliberate choice rather than a mistake.
    const sections = ['dashboard', 'estate', 'risk', 'network', 'policy', 'admin'];
    const dark = CSS.slice(CSS.indexOf('prefers-color-scheme: dark'));

    for (const section of sections) {
      expect(CSS).toContain(`--sec-${section}:`);
      expect(dark, `--sec-${section} has no dark value`).toContain(`--sec-${section}:`);
    }
  });

  it('never uses a bare 1fr grid track', () => {
    // `1fr` means `minmax(auto, 1fr)`, so the track refuses to shrink below its
    // content: one long unbroken string — a digest, a config line, a JMESPath
    // expression — pushes the column past its container and over whatever is beside
    // it. `minmax(0, 1fr)` is the fix, and it is invisible until something overflows.
    const offenders = WITHOUT_COMMENTS.split('\n')
      .map((line, index) => [index + 1, line.trim()] as const)
      .filter(([, line]) => line.startsWith('grid-template-columns'))
      // `repeat(auto-fit, minmax(...))` already carries its own floor.
      .filter(([, line]) => !line.includes('repeat('))
      .filter(([, line]) => /(^|[\s:(])1fr/.test(line.replace(/minmax\([^)]*\)/g, '')));

    expect(offenders).toEqual([]);
  });
});
