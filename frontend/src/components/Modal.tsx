/** A modal dialog, with the behaviour that makes one usable by keyboard.
 *
 * **Not `<dialog showModal()>`**, which would give the focus trap, the Escape key and
 * the backdrop for free — and would put all three beyond the reach of the tests. jsdom
 * 25 does not implement `showModal`, so every property that matters here would be
 * delegated to a browser feature this suite cannot exercise, and the first regression
 * in any of them would ship silently. Hand-written, they are ordinary code with
 * ordinary tests.
 *
 * What a dialog has to do, and why each one is not optional:
 *
 * **Trap Tab.** Without it the third Tab leaves the dialog for the page underneath,
 * which is still there and still focusable, and a keyboard user is editing a form they
 * cannot see.
 *
 * **Close on Escape.** The one key everybody tries, and the only way out that does not
 * require finding a control first.
 *
 * **Give focus back.** Closing unmounts whatever was focused, which drops focus to
 * `<body>` and restarts a keyboard user at the top of the document — several screens
 * away from the row they opened.
 *
 * **Lock the page behind it.** Scrolling the background while a dialog is open moves
 * the thing the reader came back to.
 *
 * Rendered through a portal so it is not clipped by an ancestor's `overflow` and does
 * not inherit a stacking context from whatever card happened to contain the trigger.
 */

import { useCallback, useEffect, useRef } from 'react';
import type { ReactNode } from 'react';
import { createPortal } from 'react-dom';

import { Icon } from './Icon';

/** Everything focusable, in document order. Queried on each Tab rather than cached:
 *  a dialog's contents change as its data loads, and a stale list traps focus on
 *  elements that are no longer there. */
const FOCUSABLE =
  'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), ' +
  'textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

export function Modal({
  label,
  onClose,
  size = 'default',
  children,
}: {
  /** What a screen reader announces on arrival. The dialog has no visible title of
   *  its own — the content supplies that — so this is the only name it gets. */
  label: string;
  onClose: () => void;
  /** `wide` for a dialog holding a table rather than prose.
   *
   *  The default is capped at a comfortable reading measure, which is right for a
   *  finding's description and wrong for five columns of figures — those get narrower
   *  as the cap bites, which is the truncation the dialog was opened to escape. */
  size?: 'default' | 'wide';
  children: ReactNode;
}) {
  const panel = useRef<HTMLDivElement>(null);

  // Captured before the dialog takes focus, restored when it goes.
  const returnTo = useRef<HTMLElement | null>(null);

  useEffect(() => {
    returnTo.current = document.activeElement as HTMLElement | null;
    panel.current?.focus();

    return () => {
      // `isConnected`: the trigger may itself have been unmounted by whatever the
      // dialog did — a delete, a filter change — and focusing a detached node
      // silently does nothing, leaving focus on `<body>` after all.
      const target = returnTo.current;
      if (target?.isConnected) target.focus();
    };
  }, []);

  useEffect(() => {
    const previous = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {
      document.body.style.overflow = previous;
    };
  }, []);

  const onKeyDown = useCallback(
    (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.stopPropagation();
        onClose();
        return;
      }
      if (event.key !== 'Tab' || !panel.current) return;

      const focusable = [...panel.current.querySelectorAll<HTMLElement>(FOCUSABLE)];
      if (focusable.length === 0) {
        // Nothing to move to, so Tab would leave for the page behind.
        event.preventDefault();
        return;
      }

      const first = focusable[0]!;
      const last = focusable[focusable.length - 1]!;
      const active = document.activeElement;

      if (event.shiftKey && (active === first || active === panel.current)) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && active === last) {
        event.preventDefault();
        first.focus();
      }
    },
    [onClose],
  );

  useEffect(() => {
    document.addEventListener('keydown', onKeyDown, true);
    return () => document.removeEventListener('keydown', onKeyDown, true);
  }, [onKeyDown]);

  return createPortal(
    <div
      className="modal"
      // `mousedown`, not `click`: a selection that starts on the text inside and ends
      // on the backdrop would otherwise close the dialog mid-drag, losing the
      // selection and the dialog together.
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <div
        className={size === 'wide' ? 'modal__panel modal__panel--wide' : 'modal__panel'}
        role="dialog"
        aria-modal="true"
        aria-label={label}
        ref={panel}
        tabIndex={-1}
      >
        {/* Named by its own visible word rather than `Close ${label}`. Only one dialog
            is ever open, and a screen reader announces the dialog's name on entry — so
            the longer label repeats what the reader has just heard on the one control
            they most need to find quickly. */}
        <button type="button" className="modal__close" onClick={onClose}>
          <Icon name="cross" size={14} />
          Close
        </button>
        {children}
      </div>
    </div>,
    document.body,
  );
}
