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
    await userEvent.click(screen.getByRole('button', { name: /Rule 2, Partner RDP/ }));

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
    await userEvent.click(screen.getByRole('button', { name: /Rule 2, Partner RDP/ }));
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
    await userEvent.click(screen.getByRole('button', { name: /Rule 1, Web/ }));

    // The object name and the resolved address are both present: the two differing is
    // often the entire problem, and showing only one hides it.
    expect(screen.getByText(/web-01/)).toBeInTheDocument();
    expect(screen.getAllByText('10.20.0.10').length).toBeGreaterThan(0);
  });

  it('warns when a rule was excluded from the analysis for unresolved objects', async () => {
    const rule = makeRule(1, 'Partner', { unresolved: ['partner-group'] });
    render(<RulebaseViewer rulebase={makeRulebase([rule])} />);
    await userEvent.click(screen.getByRole('button', { name: /Rule 1, Partner/ }));

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
