/** The rulebase viewer (FR-FW-07).
 *
 * Rules are shown in evaluation order and never sorted. That is not a missing feature:
 * shadowing *is* a statement about position, so a table sorted by name or severity
 * would make the most important finding on the page impossible to see.
 *
 * Each rule carries its own problems inline rather than in a separate list, and a
 * relationship names the rule on the other side of it with a control that scrolls
 * there — a shadowing finding is unreadable without both rules in view.
 */

import { useMemo, useRef, useState } from 'react';

import type { Rule, RuleIssue, Rulebase } from './types';
import { issueLabel, loggingLabel, worstSeverity } from './types';

interface Props {
  rulebase: Rulebase;
  /** Highlighted and scrolled to — set when a query or a related-rule link names one. */
  focusOrder?: number | null;
  onFocusOrder?: (order: number | null) => void;
}

function IssueBadge({ issue, onFollow }: { issue: RuleIssue; onFollow?: (order: number) => void }) {
  return (
    <li className="rule__issue">
      <span className={`pill pill--${issue.severity}`}>{issueLabel(issue.issue)}</span>
      <span className="rule__issue-text">{issue.message}</span>
      {issue.related_rule_order != null && onFollow && (
        <button
          type="button"
          className="button button--ghost button--small"
          onClick={() => onFollow(issue.related_rule_order as number)}
        >
          Go to #{issue.related_rule_order}
        </button>
      )}
    </li>
  );
}

function RuleRow({
  rule,
  focused,
  expanded,
  onToggle,
  onFollow,
}: {
  rule: Rule;
  focused: boolean;
  expanded: boolean;
  onToggle: () => void;
  onFollow: (order: number) => void;
}) {
  const severity = worstSeverity(rule);
  const classes = [
    'rule',
    `rule--${severity}`,
    rule.enabled ? '' : 'rule--disabled',
    focused ? 'rule--focused' : '',
  ]
    .filter(Boolean)
    .join(' ');

  return (
    <li className={classes} id={`rule-${rule.order}`} data-testid={`rule-${rule.order}`}>
      <button
        type="button"
        className="rule__summary"
        onClick={onToggle}
        aria-expanded={expanded}
        aria-label={`Rule ${rule.order}, ${rule.name}`}
      >
        <span className="rule__order">{rule.order}</span>
        <span className="rule__name">
          {rule.name}
          {!rule.enabled && <span className="rule__flag">disabled</span>}
        </span>
        <span className={`rule__action rule__action--${rule.permits ? 'allow' : 'deny'}`}>
          {rule.action}
        </span>
        <span className="rule__cell mono">{rule.source}</span>
        <span className="rule__cell mono">{rule.destination}</span>
        <span className="rule__cell mono">{rule.services}</span>
        <span className={`rule__log rule__log--${rule.logs === null ? 'unknown' : rule.logs}`}>
          {loggingLabel(rule.logs)}
        </span>
        <span className="rule__issue-count">
          {rule.issues.length > 0 && (
            <span className={`pill pill--${severity}`}>{rule.issues.length}</span>
          )}
        </span>
      </button>

      {expanded && (
        <div className="rule__detail">
          <dl className="kv">
            <dt>Zones</dt>
            <dd>
              {rule.src_zones.join(', ') || 'any'} &rarr; {rule.dst_zones.join(', ') || 'any'}
            </dd>
            <dt>Objects</dt>
            <dd className="mono">
              {rule.source_objects.join(', ') || 'any'} &rarr;{' '}
              {rule.destination_objects.join(', ') || 'any'} on{' '}
              {rule.service_objects.join(', ') || 'any'}
            </dd>
            {rule.applications.length > 0 && (
              <>
                <dt>Applications</dt>
                <dd>{rule.applications.join(', ')}</dd>
              </>
            )}
            <dt>Security profiles</dt>
            <dd>
              {rule.has_profiles
                ? Object.entries(rule.profiles)
                    .map(([k, v]) => `${k}: ${v}`)
                    .join(', ')
                : 'none'}
            </dd>
            {rule.hit_count != null && (
              <>
                <dt>Hits</dt>
                <dd>
                  {rule.hit_count.toLocaleString()}
                  {rule.last_hit && ` (last ${rule.last_hit})`}
                </dd>
              </>
            )}
            {rule.unresolved.length > 0 && (
              <>
                <dt>Unresolved</dt>
                <dd className="text-error">
                  {rule.unresolved.join(', ')} — this rule&rsquo;s real scope could not be
                  determined, so it is excluded from the overlap analysis.
                </dd>
              </>
            )}
          </dl>

          {rule.issues.length > 0 && (
            <ul className="rule__issues">
              {rule.issues.map((issue, index) => (
                <IssueBadge key={`${issue.issue}-${index}`} issue={issue} onFollow={onFollow} />
              ))}
            </ul>
          )}
        </div>
      )}
    </li>
  );
}

export function RulebaseViewer({ rulebase, focusOrder = null, onFocusOrder }: Props) {
  const [expanded, setExpanded] = useState<Set<number>>(new Set());
  const listRef = useRef<HTMLUListElement>(null);

  const shown = rulebase.rules;
  const hiddenCount = rulebase.total - shown.length;

  const follow = (order: number) => {
    setExpanded((current) => new Set(current).add(order));
    onFocusOrder?.(order);
    // The element may be filtered out of the DOM, in which case there is nothing to
    // scroll to and the focus highlight is all the feedback available.
    listRef.current
      ?.querySelector(`#rule-${order}`)
      ?.scrollIntoView({ behavior: 'smooth', block: 'center' });
  };

  const toggle = (order: number) =>
    setExpanded((current) => {
      const next = new Set(current);
      if (next.has(order)) next.delete(order);
      else next.add(order);
      return next;
    });

  const severityCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const rule of shown) {
      const severity = worstSeverity(rule);
      if (severity !== 'none') counts[severity] = (counts[severity] ?? 0) + 1;
    }
    return counts;
  }, [shown]);

  if (rulebase.summary.rules_total === 0) {
    return (
      <div className="alert" role="status">
        <strong>No rulebase in this snapshot.</strong>{' '}
        {rulebase.summary.limitations[0] ??
          'That is expected for a switch or router. On a firewall it means the policy was not collected or could not be parsed.'}
      </div>
    );
  }

  return (
    <div className="rulebase">
      <div className="rulebase__meta">
        <span>
          Showing <strong>{shown.length}</strong> of {rulebase.total} rules
          {hiddenCount > 0 && <span className="muted"> ({hiddenCount} hidden by filters)</span>}
        </span>
        {Object.entries(severityCounts).map(([severity, count]) => (
          <span key={severity} className={`pill pill--${severity}`}>
            {count} {severity}
          </span>
        ))}
      </div>

      {shown.length === 0 ? (
        <p className="empty">No rule matches these filters.</p>
      ) : (
        <ul className="rulebase__list" ref={listRef}>
          <li className="rule rule--head" aria-hidden="true">
            <span className="rule__summary">
              <span className="rule__order">#</span>
              <span className="rule__name">Name</span>
              <span className="rule__action">Action</span>
              <span className="rule__cell">Source</span>
              <span className="rule__cell">Destination</span>
              <span className="rule__cell">Service</span>
              <span className="rule__log">Logging</span>
              <span className="rule__issue-count" />
            </span>
          </li>
          {shown.map((rule) => (
            <RuleRow
              key={rule.order}
              rule={rule}
              focused={focusOrder === rule.order}
              expanded={expanded.has(rule.order)}
              onToggle={() => toggle(rule.order)}
              onFollow={follow}
            />
          ))}
        </ul>
      )}
    </div>
  );
}
