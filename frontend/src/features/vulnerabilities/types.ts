/** Vulnerability types, mirroring netsecops/schemas/vulnerability.py.
 *
 * Every nullable field below is nullable on purpose, and the page is written so that
 * `null` and `false` never render the same:
 *
 * - `kev: null` means the KEV catalogue has never been imported. `kev: false` means it
 *   has and this CVE is not on it. Shown identically, an estate nobody has checked
 *   looks like an estate that checked and is clean.
 * - `epss: null` means unscored, not harmless.
 * - `confidence: 'not_evaluated'` means the question could not be asked — no version
 *   collected, an unreadable range, two incomparable release trains. It is not a weak
 *   'confirmed'.
 */

export type MatchConfidence = 'confirmed' | 'likely' | 'not_affected' | 'not_evaluated';

export interface Cvss {
  version: string | null;
  base_score: number | null;
  base_severity: string | null;
  vector: string | null;
}

export interface Vulnerability {
  finding_id: string;
  device_id: string;
  device_hostname: string | null;
  title: string;
  severity: string;
  status: string;
  advisory_id: string | null;
  advisory_source: string | null;
  cve_ids: string[];
  cwe_ids: string[];
  cvss: Cvss | null;
  epss: number | null;
  kev: boolean | null;
  kev_due_date: string | null;
  confidence: MatchConfidence | null;
  /** Why the matcher reached its verdict. What makes a 'likely' actionable. */
  reasoning: string[];
  installed_version: string | null;
  fixed_versions: string[];
  remediations: string[];
  references: string[];
  published: string | null;
  modified: string | null;
  first_seen_at: string | null;
  last_seen_at: string | null;
}

export interface AffectedDevice {
  device_id: string;
  hostname: string | null;
  mgmt_ip: string | null;
  platform: string | null;
  installed_version: string | null;
  confidence: MatchConfidence;
  fixed_versions: string[];
  finding_status: string | null;
}

export interface AdvisorySummary {
  source: string;
  advisory_id: string;
  title: string | null;
  /** False when a statement in the advisory defeated the parser. Such an advisory can
   *  raise a finding but can never clear a device, which changes how much weight a
   *  'not affected' verdict deserves. */
  fully_interpreted: boolean;
  unparsed_statements: string[];
  references: string[];
}

export interface CveDetail {
  cve_id: string;
  description: string | null;
  cvss31: Cvss | null;
  cvss40: Cvss | null;
  cwe_ids: string[];
  epss: number | null;
  kev: boolean | null;
  kev_due_date: string | null;
  published: string | null;
  modified: string | null;
  advisories: AdvisorySummary[];
  affected_devices: AffectedDevice[];
  /** Devices the matcher could not rule on. Neither affected nor clear. */
  unevaluated_devices: AffectedDevice[];
}

export interface FeedStatus {
  feed: string;
  mode: string;
  status: 'succeeded' | 'partial' | 'failed';
  started_at: string;
  finished_at: string | null;
  advisories_ingested: number;
  cves_ingested: number;
  eol_records_ingested: number;
  kev_entries_ingested: number;
  epss_scores_ingested: number;
  records_rejected: number;
  /** The feed's own version or date stamp — CISA's catalogVersion, EPSS's score_date —
   *  as opposed to when the import ran. Null for feeds that carry no such stamp. */
  source_version: string | null;
  error_message: string | null;
}

export interface VulnerabilitySummary {
  total: number;
  by_severity: Record<string, number>;
  by_confidence: Record<string, number>;
  kev_count: number;
  devices_affected: number;
  /** Devices with no assessment on record — not devices found clean. */
  devices_unassessed: number;
}

export const CONFIDENCE_LABELS: Record<MatchConfidence, string> = {
  confirmed: 'Confirmed',
  likely: 'Likely',
  not_affected: 'Not affected',
  not_evaluated: 'Not evaluated',
};

/** What each verdict actually claims, in the tooltip where someone will read it. */
export const CONFIDENCE_MEANINGS: Record<MatchConfidence, string> = {
  confirmed: 'The version matches and every condition the advisory states is satisfied.',
  likely:
    'The version matches, but a condition the advisory states could not be established either way. This is an unanswered question, not a weak confirmation.',
  not_affected: 'The advisory was fully understood and nothing in it applies to this device.',
  not_evaluated:
    'The question could not be asked — no version was collected, the affected range was unreadable, or the release trains are not comparable. This device is neither affected nor clear.',
};

// ───────────────────── upgrade path (FR-VUL-10) ──────────────────────────────

/** One release this device could move to, and what moving there would close. */
export interface UpgradeCandidate {
  version: string;
  eliminates: string[];
  remaining: string[];
  /** Neither closed nor left open: the two releases are not comparable. Never folded
   *  into the other two, because Cisco IOS trains have independent fix schedules and
   *  `15.2(7)E3` is not later than `15.2(4)M5`. */
  undetermined: string[];
  eliminates_count: number;
  remaining_count: number;
  undetermined_count: number;
  kev_eliminated: number;
  advisories_closed: number;
}

export interface UpgradeReport {
  device_id: string;
  hostname: string | null;
  platform: string | null;
  current_version: string | null;
  /** The device's own version could not be parsed, so no candidate was filtered
   *  against it. The difference between a caveated answer and a wrong one. */
  current_version_unparsed: boolean;
  total_open_cves: number;
  candidates: UpgradeCandidate[];
}

// ──────────────────── CPE coverage (FR-VUL-02) ───────────────────────────────

export type Corroboration = 'corroborated' | 'contradicted' | 'no-evidence';

/** One platform's CPE product name, and whether the imported corpus backs it up. */
export interface ProductCoverage {
  platform: string;
  vendor: string;
  product: string;
  status: Corroboration;
  /** The product names the corpus *does* carry for this vendor. On a contradiction the
   *  right name is usually visibly among them. */
  vendor_products_seen: string[];
  advisories_for_vendor: number;
  /** The near-miss that triggered a contradiction. */
  closest_match: string | null;
}

export interface CpeCoverage {
  advisories_examined: number;
  products: ProductCoverage[];
  limitations: string[];
}

/** What each verdict means, spelled out where somebody will act on it.
 *
 * `no-evidence` is the one that must not be chased as a fault: it says the corpus holds
 * no advisory for that vendor at all, which is a gap in what has been imported rather
 * than a wrong name. */
export const CORROBORATION_LABELS: Record<Corroboration, string> = {
  corroborated: 'Confirmed by an advisory',
  contradicted: 'Probably wrong',
  'no-evidence': 'Nothing to check against',
};

/** KEV has three states and the third is the one that matters. */
export function kevLabel(kev: boolean | null): string {
  if (kev === true) return 'Known exploited';
  if (kev === false) return 'Not in KEV';
  return 'KEV not checked';
}

export function formatEpss(epss: number | null): string {
  return epss == null ? 'Not scored' : `${(epss * 100).toFixed(1)}%`;
}
