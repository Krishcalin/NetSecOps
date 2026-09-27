/** The heading every screen opens with (IF-UI-02).
 *
 * One component rather than twenty-seven copies of the same three elements, because
 * the copies had already drifted: some pages carried a subtitle and some did not, the
 * actions beside a title were laid out differently on each, and nothing tied a screen
 * to the navigation entry that reached it.
 *
 * The icon is the same glyph the sidebar uses for that route. That is the whole point
 * of it — a reader arriving on a page can see at a glance which entry they are on,
 * which matters most on the pages that look alike from across the room. It is
 * decorative, like every other icon here: the `<h1>` is what gets announced.
 */

import type { ReactNode } from 'react';

import { IconChip, type IconName } from './Icon';

export function PageHeader({
  icon,
  title,
  subtitle,
  tone,
  actions,
}: {
  icon: IconName;
  /** Usually a plain string. A node where the name is the thing being looked at —
   *  a device's configuration page is headed by that device, not by the word
   *  "Device" — and that title has to come out of the data. */
  title: ReactNode;
  /** One sentence on what the page answers. Optional, because a handful of screens
   *  genuinely need no gloss — but most do, and the ones that dropped it were the
   *  ones a new operator could not place. */
  subtitle?: ReactNode;
  tone?: string;
  /** Controls that belong to the page as a whole rather than to a card on it. */
  actions?: ReactNode;
}) {
  return (
    <header className="page__header">
      <div className="page__heading">
        <IconChip name={icon} tone={tone ?? 'var(--accent)'} size={19} />
        <div className="page__heading-text">
          <h1>{title}</h1>
          {subtitle && <p className="page__subtitle">{subtitle}</p>}
        </div>
        {actions && <div className="page__actions">{actions}</div>}
      </div>
    </header>
  );
}
