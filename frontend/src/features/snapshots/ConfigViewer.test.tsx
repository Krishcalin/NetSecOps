/** Component tests for the configuration viewer (IF-UI-04, TEST-05). */

import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';

import { ConfigViewer } from './ConfigViewer';

const CONFIG = [
  '!',
  'hostname core-sw-01',
  'no ip http server',
  'snmp-server community [REDACTED:community:9f3a] RO',
  'line vty 0 4',
  ' exec-timeout 5 0',
].join('\n');

describe('ConfigViewer', () => {
  it('numbers every line from one', () => {
    const { container } = render(<ConfigViewer config={CONFIG} />);

    const first = container.querySelector('[data-line="1"]');
    const last = container.querySelector('[data-line="6"]');

    expect(first).not.toBeNull();
    expect(last).not.toBeNull();
    // Operators count from one; ciscoconfparse2 counts from zero, and the backend
    // converts. A regression on either side sends findings to the wrong line.
    expect(container.querySelector('[data-line="0"]')).toBeNull();
  });

  it('marks a redaction placeholder so it does not read as real configuration', () => {
    render(<ConfigViewer config={CONFIG} />);

    expect(screen.getByText('[REDACTED:community:9f3a]')).toHaveClass('cfg__redacted');
  });

  it('finds matching lines and reports how many', async () => {
    const user = userEvent.setup();
    render(<ConfigViewer config={CONFIG} />);

    await user.type(screen.getByLabelText('Search configuration'), 'vty');

    expect(screen.getByText('1 of 1')).toBeInTheDocument();
  });

  it('says when a search matches nothing', async () => {
    const user = userEvent.setup();
    render(<ConfigViewer config={CONFIG} />);

    await user.type(screen.getByLabelText('Search configuration'), 'ospf');

    expect(screen.getByText('no matches')).toBeInTheDocument();
  });

  it('steps through multiple matches', async () => {
    const user = userEvent.setup();
    render(<ConfigViewer config={CONFIG} />);

    await user.type(screen.getByLabelText('Search configuration'), 'server');
    expect(screen.getByText('1 of 2')).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Next' }));
    expect(screen.getByText('2 of 2')).toBeInTheDocument();

    // And wraps, rather than dead-ending on the last hit.
    await user.click(screen.getByRole('button', { name: 'Next' }));
    expect(screen.getByText('1 of 2')).toBeInTheDocument();
  });

  it('highlights the line a finding linked to', () => {
    const { container } = render(<ConfigViewer config={CONFIG} jumpToLine={3} />);

    expect(container.querySelector('[data-line="3"]')).toHaveClass('cfg__line--target');
  });

  it('marks lines a diff reported as changed', () => {
    const { container } = render(<ConfigViewer config={CONFIG} highlightLines={new Set([2, 5])} />);

    expect(container.querySelector('[data-line="2"]')).toHaveClass('cfg__line--changed');
    expect(container.querySelector('[data-line="4"]')).not.toHaveClass('cfg__line--changed');
  });

  it('renders an empty configuration without crashing', () => {
    const { container } = render(<ConfigViewer config="" />);
    expect(container.querySelectorAll('.cfg__line')).toHaveLength(1);
  });
});
