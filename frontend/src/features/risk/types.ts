/** Estate risk types, mirroring netsecops/schemas/risk.py.
 *
 * Every response here ships its own legend — the six grade bands, the four priority
 * bands, the twenty-cell matrix — because the server computes them from the same
 * functions that assigned the letters and buckets in the payload. Nothing in this
 * folder hard-codes a threshold, a band boundary or a meaning: a copy here would be
 * free to say `B` where `grading.py` said `C`, and it is the copy a reader sees.
 */

export type Grade = 'A' | 'B' | 'C' | 'D' | 'E' | 'F';
export type Priority = 'P1' | 'P2' | 'P3' | 'P4';
export type Direction = 'improving' | 'worsening' | 'steady' | 'unknown';

export interface GradeBand {
  letter: Grade;
  /** Inclusive bounds on the 0–100 risk score, in which **0 is clean**. */
  floor: number;
  ceiling: number;
  meaning: string;
}

export interface DeviceGrade {
  device_id: string;
  /** Unresolved, as everywhere else in the console: fall back to `mgmt_ip`. */
  hostname: string | null;
  mgmt_ip: string;
  device_class: string;
  criticality: string;
  /** `null` for a device nobody has assessed — not zero, which is a clean device.
   *  `grade` is `null` in exactly the same case. */
  score: number | null;
  grade: Grade | null;
  assessed_at: string | null;
  open_findings: number;
  worst_priority: Priority | null;
}

export interface GradeReport {
  /** The worst devices, capped by the request's limit. `total_devices` is how many
   *  are in scope; everything below it describes the whole scope, not this slice. */
  devices: DeviceGrade[];
  total_devices: number;
  by_grade: Record<string, number>;
  ungraded: number;
  estate_score: number | null;
  estate_grade: Grade | null;
  bands: GradeBand[];
}

export interface MatrixCell {
  severity: string;
  criticality: string;
  /** Severity weight × criticality multiplier — the product the risk score sums. */
  weight: number;
  priority: Priority;
}

export interface PriorityBand {
  code: Priority;
  label: string;
  floor: number;
  meaning: string;
}

export interface PriorityBucket {
  code: Priority;
  open: number;
  devices: number;
  oldest_first_seen: string | null;
  mean_age_days: number | null;
  /** A due date is only ever set by hand, so both figures are given: without the
   *  first, a nought in `overdue` reads as "nothing is late". */
  with_due_date: number;
  overdue: number;
}

export interface PriorityReport {
  buckets: PriorityBucket[];
  total_open: number;
  bands: PriorityBand[];
  matrix: MatrixCell[];
}

export interface EstateRiskPoint {
  day: string;
  /** `null` before anything in scope was assessed — a break in the line, not a nought. */
  score: number | null;
  grade: Grade | null;
  /** How many devices the figure is a roll-up of. */
  devices: number;
  /** Assessments on this day; nought means the score was carried forward. */
  assessed: number;
}

export interface EstateRiskTrend {
  days: number;
  since: string;
  points: EstateRiskPoint[];
  direction: Direction;
  latest_score: number | null;
  latest_grade: Grade | null;
}

/** Spelled out rather than drawn as an arrow. Risk counts down here, so an arrow
 *  would be ambiguous even before a screen reader skipped it. */
export const DIRECTION_LABELS: Record<Direction, string> = {
  improving: 'improving',
  worsening: 'getting worse',
  steady: 'unchanged',
  unknown: 'no direction yet',
};

/** The severity ramp, applied to grades on purpose.
 *
 * `sections.ts` keeps the navigation hues *outside* this ramp so a page header is
 * never mistaken for a verdict. A grade is the opposite case: it **is** a verdict,
 * and giving it the same colours as a critical finding is what makes the two agree.
 * Every letter is also printed, so the ramp is never the only carrier (WCAG 1.4.1).
 */
export const GRADE_TONES: Record<Grade, string> = {
  A: 'var(--sev-low)',
  B: 'var(--sev-low)',
  C: 'var(--sev-medium)',
  D: 'var(--sev-high)',
  E: 'var(--sev-high)',
  F: 'var(--sev-critical)',
};

export const PRIORITY_TONES: Record<Priority, string> = {
  P1: 'var(--sev-critical)',
  P2: 'var(--sev-high)',
  P3: 'var(--sev-medium)',
  P4: 'var(--sev-info)',
};
