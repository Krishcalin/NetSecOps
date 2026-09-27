/** The dialog's keyboard behaviour.
 *
 * All of it would have come free from `<dialog showModal()>`, and none of it would
 * have been testable: jsdom 25 does not implement `showModal`, so the trap, the Escape
 * key and the focus restore would be delegated to a browser feature this suite cannot
 * exercise. Written by hand, they are ordinary code — and these are the tests that pay
 * for that decision.
 *
 * Each one is a way a dialog fails a keyboard user while looking perfectly correct to
 * a mouse: Tab escapes to a page they cannot see, Escape does nothing, or closing
 * drops them back at the top of the document several screens from where they were.
 */

import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { useState } from 'react';
import { describe, expect, it } from 'vitest';

import { Modal } from './Modal';

/** A page with something focusable behind the dialog, which is what makes the trap
 *  testable at all — with nothing behind it, Tab has nowhere wrong to go. */
function Harness({ withFields = true }: { withFields?: boolean }) {
  const [open, setOpen] = useState(false);

  return (
    <div>
      <button onClick={() => setOpen(true)}>Open</button>
      <button>Behind the dialog</button>
      {open && (
        <Modal label="Test dialog" onClose={() => setOpen(false)}>
          {withFields && (
            <>
              <button>First inside</button>
              <button>Last inside</button>
            </>
          )}
        </Modal>
      )}
    </div>
  );
}

describe('Modal', () => {
  it('announces itself as a modal dialog with a name', async () => {
    const user = userEvent.setup();
    render(<Harness />);

    await user.click(screen.getByRole('button', { name: 'Open' }));

    const dialog = await screen.findByRole('dialog', { name: 'Test dialog' });
    expect(dialog).toHaveAttribute('aria-modal', 'true');
  });

  it('takes focus when it opens', async () => {
    // Otherwise the caret stays on the trigger behind the dialog, nothing is
    // announced, and a screen-reader user has no idea anything appeared.
    const user = userEvent.setup();
    render(<Harness />);

    await user.click(screen.getByRole('button', { name: 'Open' }));

    await waitFor(() => expect(screen.getByRole('dialog')).toHaveFocus());
  });

  it('closes on Escape', async () => {
    const user = userEvent.setup();
    render(<Harness />);
    await user.click(screen.getByRole('button', { name: 'Open' }));
    await screen.findByRole('dialog');

    await user.keyboard('{Escape}');

    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
  });

  it('closes when the backdrop is clicked', async () => {
    const user = userEvent.setup();
    const { container } = render(<Harness />);
    await user.click(screen.getByRole('button', { name: 'Open' }));
    await screen.findByRole('dialog');

    const backdrop = document.querySelector('.modal')!;
    await user.click(backdrop as HTMLElement);

    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(container).toBeTruthy();
  });

  it('does not close when the panel itself is clicked', async () => {
    // The click lands on the dialog, not the backdrop. Closing here would make the
    // dialog vanish whenever somebody clicked its own text.
    const user = userEvent.setup();
    render(<Harness />);
    await user.click(screen.getByRole('button', { name: 'Open' }));

    await user.click(await screen.findByRole('dialog'));

    expect(screen.getByRole('dialog')).toBeInTheDocument();
  });

  it('gives focus back to what opened it', async () => {
    // Closing unmounts the dialog, which drops focus to <body> and restarts a
    // keyboard user at the top of the document.
    const user = userEvent.setup();
    render(<Harness />);
    const trigger = screen.getByRole('button', { name: 'Open' });
    await user.click(trigger);
    await screen.findByRole('dialog');

    await user.keyboard('{Escape}');

    await waitFor(() => expect(trigger).toHaveFocus());
  });

  it('keeps Tab inside the dialog', async () => {
    // The page behind is still there and still focusable. Without the trap, a few
    // Tabs put the caret on controls the reader cannot see.
    const user = userEvent.setup();
    render(<Harness />);
    await user.click(screen.getByRole('button', { name: 'Open' }));
    await screen.findByRole('dialog');

    // Close, First, Last — then round to the start rather than out to the page.
    await user.tab();
    await user.tab();
    await user.tab();
    await user.tab();

    expect(screen.getByRole('button', { name: 'Behind the dialog' })).not.toHaveFocus();
    expect(document.activeElement?.textContent).toContain('Close');
  });

  it('wraps backwards too', async () => {
    const user = userEvent.setup();
    render(<Harness />);
    await user.click(screen.getByRole('button', { name: 'Open' }));
    await screen.findByRole('dialog');

    // Shift+Tab from the dialog itself goes to the last control inside it, not back
    // out to the page.
    await user.tab({ shift: true });

    expect(screen.getByRole('button', { name: 'Last inside' })).toHaveFocus();
  });

  it('holds focus even with nothing focusable but its own close button', async () => {
    const user = userEvent.setup();
    render(<Harness withFields={false} />);
    await user.click(screen.getByRole('button', { name: 'Open' }));
    await screen.findByRole('dialog');

    await user.tab();
    await user.tab();

    expect(screen.getByRole('button', { name: 'Behind the dialog' })).not.toHaveFocus();
  });

  it('locks the page behind it and releases it again', async () => {
    // Scrolling the background moves the thing the reader came back to.
    const user = userEvent.setup();
    render(<Harness />);

    await user.click(screen.getByRole('button', { name: 'Open' }));
    await screen.findByRole('dialog');
    expect(document.body.style.overflow).toBe('hidden');

    await user.keyboard('{Escape}');
    await waitFor(() => expect(document.body.style.overflow).not.toBe('hidden'));
  });

  it('offers Close as the first thing inside it', async () => {
    // Top of the dialog and first in the tab order, which is where a dialog's
    // dismiss control belongs — not at the end, after everything it contains.
    const user = userEvent.setup();
    render(<Harness />);
    await user.click(screen.getByRole('button', { name: 'Open' }));

    const dialog = await screen.findByRole('dialog');
    const buttons = [...dialog.querySelectorAll('button')].map((b) => b.textContent);
    expect(buttons[0]).toContain('Close');
  });
});
