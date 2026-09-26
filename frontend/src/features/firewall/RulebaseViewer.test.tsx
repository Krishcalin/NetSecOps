/** Component tests for the rulebase viewer (FR-FW-07, TEST-05).
 *
 * Three behaviours here are load-bearing, and each would be invisible if it broke:
 *
 * **Evaluation order.** Shadowing *is* a statement about position, so a viewer that
 * sorted by severity — the obvious thing to do with a list of problems — would make its
 * most important finding impossible to see.
 *
 * **Three logging states.** `null` means the parser could not tell, and rendering it as
 * "no" sends someone to enable logging on a rule that already has it.
 *
 * **No rulebase is not a clean rulebase.** Both arrive as an empty list, and only one of
 * them is good news.
 */

import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';

import { RulebaseViewer } from './RulebaseViewer';
import type { Rule, Rulebase, RuleIssue } from './types';

function makeRule(order: number, name: string, overrides: Partial<Rule> = {}): Rule {
  return {
    order,
    name,
    enabled: true,
    action: 'allow',
    permits: true,
    src_zones: ['untrust'],
    dst_zones: ['dmz'],
    source: 'any',
    destination: '10.20.0.10',
    services: 'tcp/443',
    source_objects: ['any'],
    destination_objects: ['web-01'],
    service_objects: ['svc-https'],
    applications: [],
    users: [],
    logs: true,
    has_profiles: false,
    profiles: {},
    schedule: null,
    hit_count: null,
    last_hit: null,
    unresolved: [],
    source_size: 4294967296,
    destination_size: 1,
    permissiveness: {
      score: 33,
      band: 'moderate',
      source: 100,
      destination: 0,
      service: 0,
      understated: false,
    },
    issues: [],
    ...overrides,
  };
}

function shadowIssue(order: number, name: string): RuleIssue {
  return {
    issue: 'shadowed',
    severity: 'high',
    message: `#${order} already matches everything this rule does, and denies it instead`,
    related_rule_order: order,
    related_rule_name: name,
  };
}

function makeRulebase(rules: Rule[], overrides: Partial<Rulebase> = {}): Rulebase {
  return {
    device_id: 'device-1',
    snapshot_id: 'snapshot-1',
    platform: 'panos',
    zones: ['untrust', 'dmz'],
    summary: {
      rules_total: rules.length,
      rules_enabled: rules.filter((r) => r.enabled).length,
      rules_analysed: rules.filter((r) => r.enabled).length,
      relationships: {},
      policy_issues: {},
      hygiene_issues: {},
      nat_issues: {},
      analysis_ms: 3,
      truncated: false,
      exposure_analysed: true,
      limitations: ['Pairwise only: a rule shadowed by several rules together is not detected.'],
    },
    rules,
    nat_rules: [],
    hygiene: [],
    total: rules.length,
    ...overrides,
  };
}

describe('RulebaseViewer', () => {
  it('shows rules in evaluation order, never sorted by severity', async () => {
    const rulebase = makeRulebase([
      makeRule(1, 'Block RDP', { action: 'deny', permits: false }),
      makeRule(2, 'Partner RDP', { issues: [shadowIssue(1, 'Block RDP')] }),
      makeRule(3, 'Inbound web'),
    ]);

    render(<RulebaseViewer rulebase={rulebase} />);

    const rows = screen.getAllByRole('listitem').filter((el) => el.id.startsWith('rule-'));
    expect(rows.map((el) => el.id)).toEqual(['rule-1', 'rule-2', 'rule-3']);
  });

  it('attaches a shadowing finding to the rule it is about, naming the cause', async () => {
    const rulebase = makeRulebase([
      makeRule(1, 'Block RDP', { action: 'deny', permits: false }),
      makeRule(2, 'Partner RDP', { issues: [shadowIssue(1, 'Block RDP')] }),
    ]);

    render(<RulebaseViewer rulebase={rulebase} />);
    await userEvent.click(screen.getByRole('button', { name: /Rule 2\s+Partner RDP/ }));

    const row = screen.getByTestId('rule-2');
    expect(within(row).getByText('Shadowed')).toBeInTheDocument();
    expect(within(row).getByRole('button', { name: 'Go to #1' })).toBeInTheDocument();
  });

  it('lets the operator jump to the rule on the other side of a relationship', async () => {
    const onFocus = vi.fn();
    const rulebase = makeRulebase([
      makeRule(1, 'Block RDP', { action: 'deny', permits: false }),
      makeRule(2, 'Partner RDP', { issues: [shadowIssue(1, 'Block RDP')] }),
    ]);

    render(<RulebaseViewer rulebase={rulebase} onFocusOrder={onFocus} />);
    await userEvent.click(screen.getByRole('button', { name: /Rule 2\s+Partner RDP/ }));
    await userEvent.click(screen.getByRole('button', { name: 'Go to #1' }));

    expect(onFocus).toHaveBeenCalledWith(1);
  });

  describe('logging has three states, not two', () => {
    it('renders a rule that logs', () => {
      render(<RulebaseViewer rulebase={makeRulebase([makeRule(1, 'A', { logs: true })])} />);
      expect(screen.getByText('logged')).toBeInTheDocument();
    });

    it('renders a rule that does not log', () => {
      render(<RulebaseViewer rulebase={makeRulebase([makeRule(1, 'A', { logs: false })])} />);
      expect(screen.getByText('not logged')).toBeInTheDocument();
    });

    it('renders "unknown" rather than "not logged" when the parser could not tell', () => {
      render(<RulebaseViewer rulebase={makeRulebase([makeRule(1, 'A', { logs: null })])} />);

      expect(screen.getByText('unknown')).toBeInTheDocument();
      expect(screen.queryByText('not logged')).not.toBeInTheDocument();
    });
  });

  it('shows a disabled rule rather than hiding it, but marks it', () => {
    render(
      <RulebaseViewer rulebase={makeRulebase([makeRule(1, 'Old rule', { enabled: false })])} />,
    );

    expect(screen.getByText('Old rule')).toBeInTheDocument();
    expect(screen.getByText('disabled')).toBeInTheDocument();
  });

  it('shows what a rule says as well as what it resolves to', async () => {
    render(<RulebaseViewer rulebase={makeRulebase([makeRule(1, 'Web')])} />);
    await userEvent.click(screen.getByRole('button', { name: /Rule 1\s+Web/ }));

    // The object name and the resolved address are both present: the two differing is
    // often the entire problem, and showing only one hides it.
    expect(screen.getByText(/web-01/)).toBeInTheDocument();
    expect(screen.getAllByText('10.20.0.10').length).toBeGreaterThan(0);
  });

  it('warns when a rule was excluded from the analysis for unresolved objects', async () => {
    const rule = makeRule(1, 'Partner', { unresolved: ['partner-group'] });
    render(<RulebaseViewer rulebase={makeRulebase([rule])} />);
    await userEvent.click(screen.getByRole('button', { name: /Rule 1\s+Partner/ }));

    expect(screen.getByText(/excluded from the overlap analysis/)).toBeInTheDocument();
  });

  it('says a snapshot carries no rulebase rather than showing an empty table', () => {
    const empty = makeRulebase([], {
      summary: {
        ...makeRulebase([]).summary,
        rules_total: 0,
        limitations: ['This snapshot carries no firewall rulebase.'],
      },
    });

    render(<RulebaseViewer rulebase={empty} />);

    expect(screen.getByText(/No rulebase in this snapshot/)).toBeInTheDocument();
    expect(screen.queryByText('No rule matches these filters.')).not.toBeInTheDocument();
  });

  it('distinguishes a filter that matched nothing from a rulebase that is empty', () => {
    const filtered = makeRulebase([], { total: 40 });
    filtered.summary.rules_total = 40;

    render(<RulebaseViewer rulebase={filtered} />);

    expect(screen.getByText('No rule matches these filters.')).toBeInTheDocument();
    expect(screen.queryByText(/No rulebase in this snapshot/)).not.toBeInTheDocument();
  });

  it('says how many rules the filters are hiding', () => {
    const rulebase = makeRulebase([makeRule(1, 'Visible')], { total: 12 });
    render(<RulebaseViewer rulebase={rulebase} />);

    expect(screen.getByText(/11 hidden by filters/)).toBeInTheDocument();
  });
});

describe('what a screen reader is told about a rule', () => {
  // `aria-label` on the rule button used to read `Rule ${order}, ${name}` — and an
  // aria-label *replaces* the element's whole subtree in the accessibility tree, so
  // everything a rulebase is read for was unreachable: action, source, destination,
  // service, logging. The label is gone and each cell carries its own hidden label.

  it('includes the action, addresses, service and logging in the name', async () => {
    const rule = makeRule(1, 'Web', { action: 'allow', source: 'any', destination: '10.20.0.10' });
    render(<RulebaseViewer rulebase={makeRulebase([rule])} />);

    const button = screen.getByRole('button', { name: /Rule 1\s+Web/ });
    const name = button.getAttribute('aria-label') ?? button.textContent ?? '';

    expect(name).toMatch(/action\s+allow/);
    expect(name).toMatch(/source\s+any/);
    expect(name).toMatch(/destination\s+10\.20\.0\.10/);
    expect(name).toMatch(/service\s+tcp\/443/);
    expect(name).toMatch(/logging/);
  });

  it('says how severe the issues are, not only how many', async () => {
    // The pill's visible text is a bare count; severity was carried by colour alone,
    // and `medium` and `low` were styled identically so it was not reliably carried
    // even for a sighted reader.
    const rule = makeRule(1, 'Web', { issues: [shadowIssue(2, 'Other')] });
    render(<RulebaseViewer rulebase={makeRulebase([rule])} />);

    const button = screen.getByRole('button', { name: /Rule 1\s+Web/ });
    expect(button.textContent).toMatch(/high issues/);
  });

  it('keeps the decorative header row out of the accessibility tree', async () => {
    // Correct now that every cell is self-labelling: exposed, it would read as a stray
    // list item of seven disconnected words.
    const { container } = render(<RulebaseViewer rulebase={makeRulebase([makeRule(1, 'Web')])} />);

    expect(container.querySelector('.rule--head')).toHaveAttribute('aria-hidden', 'true');
  });

  describe('the breadth score', () => {
    it('shows a deny rule as not applicable rather than as zero', () => {
      // A deny matching everything is the implicit-deny catch-all, the best rule on
      // most boxes. Rendering 0 would put it at the top of a "tightest rules" sort and
      // invite someone to treat the widest deny as the safest line on the firewall.
      const deny = makeRule(1, 'Block all', {
        action: 'deny',
        permits: false,
        permissiveness: null,
      });
      const { container } = render(<RulebaseViewer rulebase={makeRulebase([deny])} />);

      const cell = container.querySelector('#rule-1 .rule__perm');
      expect(cell).toHaveClass('rule__perm--none');
      expect(cell?.textContent).not.toMatch(/\d/);
      expect(cell?.textContent).toMatch(/breadth not scored/);
    });

    it('names the band in text, not by colour alone', () => {
      // The visible content is a bare number, so colour would be the only carrier of
      // the band — a WCAG 1.4.1 failure, and invisible in print or greyscale.
      render(<RulebaseViewer rulebase={makeRulebase([makeRule(1, 'Web')])} />);

      const button = screen.getByRole('button', { name: /Rule 1\s+Web/ });
      expect(button.textContent).toMatch(/33/);
      expect(button.textContent).toMatch(/breadth, moderate/);
    });

    it('marks an understated score as a floor', () => {
      // The rule names objects the rulebase never defined, so the resolved sets are
      // smaller than the real ones. Showing the number unqualified presents a lower
      // bound as a measurement.
      const rule = makeRule(1, 'Web', {
        unresolved: ['group-missing'],
        permissiveness: {
          score: 45,
          band: 'moderate',
          source: 100,
          destination: 35,
          service: 0,
          understated: true,
        },
      });
      render(<RulebaseViewer rulebase={makeRulebase([rule])} />);

      const button = screen.getByRole('button', { name: /Rule 1\s+Web/ });
      expect(button.textContent).toMatch(/≥\s*45/);
      expect(button.textContent).toMatch(/at least this, some objects are undefined/);
    });

    it('breaks the score into its components when a rule is opened', async () => {
      // "45" names nothing to change. Naming which field is wide does, and lets a
      // reviewer disagree with the score on the evidence rather than on faith.
      const user = userEvent.setup();
      render(<RulebaseViewer rulebase={makeRulebase([makeRule(1, 'Web')])} />);

      await user.click(screen.getByRole('button', { name: /Rule 1\s+Web/ }));

      expect(screen.getByText(/source 100, destination 0, service 0/)).toBeInTheDocument();
    });
  });
});
