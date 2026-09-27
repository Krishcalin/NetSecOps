/** The icon set, drawn inline (IF-UI-02).
 *
 * Hand-authored rather than pulled from a package, for one reason that is not
 * preference: SRS §2.2 says plain CSS and no UI kit, and this product ships four
 * runtime dependencies on purpose. An icon library is thirty thousand glyphs and a
 * tree-shaking configuration to avoid shipping them, in exchange for the twenty-odd
 * below.
 *
 * They follow the same grammar as the common open sets so they sit together without
 * looking assembled: a 24×24 box, `currentColor` strokes at 1.75, round caps and
 * joins, no fills. `currentColor` is the important part — an icon takes the colour of
 * whatever it is inside, so a severity tone or a hover state needs no icon variant.
 *
 * **Every icon here is decorative.** Each is `aria-hidden`, and nothing in this
 * console uses one as the only carrier of meaning: an icon always sits beside the word
 * it illustrates. That is WCAG 1.4.1, and it is also the difference between a console
 * a new operator can read and a row of pictograms they have to learn.
 */

export type IconName =
  | 'dashboard'
  | 'inventory'
  | 'credential'
  | 'assessment'
  | 'schedule'
  | 'finding'
  | 'vulnerability'
  | 'discovery'
  | 'firewall'
  | 'map'
  | 'path'
  | 'segmentation'
  | 'aaa'
  | 'check'
  | 'policy'
  | 'exception'
  | 'compliance'
  | 'report'
  | 'users'
  | 'settings'
  | 'audit'
  | 'shield'
  | 'alert'
  | 'clock'
  | 'arrow-right'
  | 'chevron'
  | 'tick'
  | 'cross'
  | 'device'
  | 'link';

/** The path data for each glyph, on a 24×24 grid. */
const PATHS: Record<IconName, string> = {
  dashboard: 'M4 13h6V4H4zM14 9h6V4h-6zM14 20h6v-9h-6zM4 20h6v-5H4z',
  inventory: 'M4 7l8-4 8 4v10l-8 4-8-4zM4 7l8 4 8-4M12 11v10',
  credential: 'M15 7a4 4 0 1 1-3.9 5H8v2H6v2H3v-3l5.1-5.1A4 4 0 0 1 15 7zM16 10h.01',
  assessment: 'M4 5h16v14H4zM8 5v14M4 9h16M4 14h16',
  schedule: 'M12 7v5l3 2M12 21a9 9 0 1 1 0-18 9 9 0 0 1 0 18z',
  finding: 'M12 3l9 16H3zM12 9v5M12 17h.01',
  vulnerability: 'M12 3l7 4v6c0 4-3 7-7 8-4-1-7-4-7-8V7zM9 12l2 2 4-4',
  discovery: 'M11 18a7 7 0 1 1 0-14 7 7 0 0 1 0 14zM20 20l-4.3-4.3',
  firewall: 'M3 5h18v14H3zM3 10h18M3 15h18M8 5v5M16 5v5M6 15v4M13 10v5M18 15v4',
  map: 'M9 4L3 7v13l6-3 6 3 6-3V4l-6 3zM9 4v13M15 7v13',
  path: 'M5 8a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM19 22a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM5 8v4a3 3 0 0 0 3 3h8a3 3 0 0 1 3 3v1',
  segmentation: 'M4 4h7v7H4zM13 13h7v7h-7zM11 7.5h2M7.5 11v2',
  aaa: 'M16 20v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2M9 10a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM18 8l2 2 3-3',
  check: 'M9 11l3 3 6-6M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0z',
  policy: 'M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8zM14 3v5h5M9 13h6M9 17h4',
  exception:
    'M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8zM14 3v5h5M9.5 13.5l5 5M14.5 13.5l-5 5',
  compliance: 'M9 12l2 2 4-4M7 3h10a2 2 0 0 1 2 2v14l-7-3-7 3V5a2 2 0 0 1 2-2z',
  report:
    'M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8zM14 3v5h5M8 17v-3M12 17v-6M16 17v-4',
  users:
    'M16 20v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2M9 10a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM22 20v-2a4 4 0 0 0-3-3.9M16 2.1a4 4 0 0 1 0 7.8',
  settings:
    'M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM19.4 15a1.6 1.6 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.6 1.6 0 0 0-2.7 1.1v.3a2 2 0 1 1-4 0v-.2a1.6 1.6 0 0 0-2.8-1.1l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.6 1.6 0 0 0-1.1-2.7H3a2 2 0 1 1 0-4h.2a1.6 1.6 0 0 0 1.1-2.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.6 1.6 0 0 0 2.7-1.1V3a2 2 0 1 1 4 0v.2a1.6 1.6 0 0 0 2.8 1.1l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.6 1.6 0 0 0 1.1 2.7h.3a2 2 0 1 1 0 4h-.2a1.6 1.6 0 0 0-1.4 1.2z',
  audit: 'M4 4h16v16H4zM8 9h8M8 13h8M8 17h4',
  shield: 'M12 3l8 4v5c0 5-3.5 8.3-8 9-4.5-.7-8-4-8-9V7z',
  alert: 'M12 3l9 16H3zM12 9v5M12 17h.01',
  clock: 'M12 7v5l3 2M12 21a9 9 0 1 1 0-18 9 9 0 0 1 0 18z',
  'arrow-right': 'M5 12h14M13 6l6 6-6 6',
  chevron: 'M9 6l6 6-6 6',
  tick: 'M5 13l4 4L19 7',
  cross: 'M6 6l12 12M18 6L6 18',
  device: 'M3 6h18v10H3zM8 20h8M12 16v4',
  link: 'M10 13a5 5 0 0 0 7 0l2-2a5 5 0 0 0-7-7l-1 1M14 11a5 5 0 0 0-7 0l-2 2a5 5 0 0 0 7 7l1-1',
};

interface Props {
  name: IconName;
  /** Pixel box. 16 in a table row, 18 in nav, 20+ in a tile chip. */
  size?: number;
  className?: string;
}

export function Icon({ name, size = 18, className }: Props) {
  return (
    <svg
      className={className}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.75}
      strokeLinecap="round"
      strokeLinejoin="round"
      // Decorative without exception: the word it sits beside is what is read out.
      // An icon announced as well would double every nav item and every tile.
      aria-hidden="true"
      focusable="false"
    >
      <path d={PATHS[name]} />
    </svg>
  );
}

/** An icon on its own tinted square — the shape a tile or a panel head uses.
 *
 * `tone` is any colour token; it drives both the glyph and a faint wash behind it, so
 * one value keeps the pair in step instead of two that can drift apart.
 */
export function IconChip({
  name,
  tone = 'var(--accent)',
  size = 20,
}: {
  name: IconName;
  tone?: string;
  size?: number;
}) {
  return (
    <span
      className="iconchip"
      style={{ color: tone, background: `color-mix(in srgb, ${tone} 12%, transparent)` }}
    >
      <Icon name={name} size={size} />
    </span>
  );
}
