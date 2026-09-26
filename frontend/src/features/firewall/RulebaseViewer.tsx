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

/** The breadth score, in the summary row.
 *
 * Three states, and collapsing any two of them would misinform:
 *
 * A **deny rule has no score**, shown as an em dash rather than 0. A deny matching
 * everything is the implicit-deny catch-all — the best rule on most boxes — and a 0
 * would sort it to the top of a list of the tightest rules.
 *
 * An **understated score is prefixed with ≥**, because the rule names objects the
 * rulebase never defined: its real breadth is at least this and probably more.
 *
 * The **band is never carried by colour alone** (WCAG 1.4.1). The visible content is a
 * bare number, so the band is named in text for assistive technology, the same way the
 * issue-count pill names its severity.
 */
function PermissivenessCell({ rule }: { rule: Rule }) {
  const score = rule.permissiveness;

  if (!score) {
    return (
      <span className="rule__perm rule__perm--none">
        <span className="visually-hidden">breadth not scored, this rule denies traffic</span>
        <span aria-hidden="true">&mdash;</span>
      </span>
    );
  }

  return (
    <span className="rule__perm">
      <span className={`pill pill--perm-${score.band}`}>
        {score.understated && <span aria-hidden="true">&ge;</span>}
        {score.score}
        <span className="visually-hidden">
          {' '}
          breadth, {score.band}
          {score.understated && ' — at least this, some objects are undefined'}
        </span>
      </span>
    </span>
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
      {/* No `aria-label` here, deliberately. It used to read
          `Rule ${order}, ${name}` — and an aria-label *replaces* the element's whole
          subtree in the accessibility tree, so a screen reader announced the number and
          the name and then stopped. Action, source, destination, service and logging —
          everything a rulebase is read for — were silently unreachable.

          The visible column header cannot supply those names either: the cells sit
          inside this button, so they cannot legally be table cells of a row above. Each
          cell therefore carries its own label, hidden visually and present for assistive
          technology, and the accessible name composes in reading order. */}
      <button type="button" className="rule__summary" onClick={onToggle} aria-expanded={expanded}>
        <span className="rule__order">
          <span className="visually-hidden">Rule </span>
          {rule.order}
        </span>
        <span className="rule__name">
          {rule.name}
          {!rule.enabled && <span className="rule__flag">disabled</span>}
        </span>
        <span className={`rule__action rule__action--${rule.permits ? 'allow' : 'deny'}`}>
          <span className="visually-hidden">action </span>
          {rule.action}
        </span>
        <span className="rule__cell mono">
          <span className="visually-hidden">source </span>
          {rule.source}
        </span>
        <span className="rule__cell mono">
          <span className="visually-hidden">destination </span>
          {rule.destination}
        </span>
        <span className="rule__cell mono">
          <span className="visually-hidden">service </span>
          {rule.services}
        </span>
        <span className={`rule__log rule__log--${rule.logs === null ? 'unknown' : rule.logs}`}>
          <span className="visually-hidden">logging </span>
          {loggingLabel(rule.logs)}
        </span>
        <PermissivenessCell rule={rule} />
        <span className="rule__issue-count">
          {rule.issues.length > 0 && (
            // The pill's visible text is a bare count; the severity was carried by its
            // colour alone, which is a WCAG 1.4.1 failure and also indistinguishable in
            // print. Worse, `medium` and `low` were styled identically, so the colour
            // did not even carry it reliably for a sighted reader.
            <span className={`pill pill--${severity}`}>
              {rule.issues.length}
              <span className="visually-hidden"> {severity} issues</span>
            </span>
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
            {rule.permissiveness && (
              <>
                <dt>Breadth</dt>
                {/* The components, not just the total. "73" names nothing an operator
                    can change; "source any, destination 10.0.0.0/8" names the field to
                    narrow — and lets them disagree with the score on the evidence. */}
                <dd>
                  {rule.permissiveness.understated && '≥'}
                  {rule.permissiveness.score}/100 ({rule.permissiveness.band}) — source{' '}
                  {rule.permissiveness.source}, destination {rule.permissiveness.destination},
                  service {rule.permissiveness.service}
                  {rule.permissiveness.understated && (
                    <span className="text-error">
                      {' '}
                      — a floor, not a measurement: this rule names objects the rulebase never
                      defined, so its real scope is wider than what was scored.
                    </span>
                  )}
                </dd>
              </>
            )}
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
        {/* These already name their severity in text, so they need no hidden label —
            unlike the per-rule pill, whose visible content is only a number. */}
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
          {/* Hidden from assistive technology on purpose, and now correctly so: every
              cell below carries its own label, making this row pure visual affordance.
              Exposing it would read as a stray list item of seven disconnected words,
              because these are not table headers and cannot be — the cells they would
              describe live inside each row's button. */}
          <li className="rule rule--head" aria-hidden="true">
            <span className="rule__summary">
              <span className="rule__order">#</span>
              <span className="rule__name">Name</span>
              <span className="rule__action">Action</span>
              <span className="rule__cell">Source</span>
              <span className="rule__cell">Destination</span>
              <span className="rule__cell">Service</span>
              <span className="rule__log">Logging</span>
              <span className="rule__perm">Breadth</span>
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
