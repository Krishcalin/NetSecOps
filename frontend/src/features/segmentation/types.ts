/** Segmentation policy types, mirroring netsecops/schemas/segmentation.py. */

export interface Zone {
  id: string;
  name: string;
  description: string | null;
  prefixes: string[];
}

export type Expectation = 'allowed' | 'denied';

export interface IntentRule {
  id: string;
  source_zone_id: string;
  destination_zone_id: string;
  expectation: Expectation;
  protocol: string;
  port: number;
  justification: string;
}

export interface ZoneCreate {
  name: string;
  description: string | null;
  prefixes: string[];
}

export interface RuleCreate {
  source_zone_id: string;
  destination_zone_id: string;
  expectation: Expectation;
  protocol: string;
  port: number;
  justification: string;
}

/** The shortest justification the API accepts. Mirrored here so the form can say so
 *  before a submit rather than after one — the server's 422 arrives with the field
 *  already forgotten. */
export const MIN_JUSTIFICATION = 10;

export type CellStatus = 'upheld' | 'violated' | 'unverified';

export interface Cell {
  rule_id: string;
  source_zone: string;
  destination_zone: string;
  expectation: Expectation;
  protocol: string;
  port: number;
  status: CellStatus;
  detail: string;
  justification: string;
  /** The prefix pairs actually walked. A cell speaks only for these. */
  walked: string[];
  limitations: string[];
}

export interface Matrix {
  cells: Cell[];
  upheld: number;
  violated: number;
  /** Never folded into `upheld`. See the note on STATUS_LABELS below. */
  unverified: number;
  limitations: string[];
}

/** How each status reads, and how it is coloured.
 *
 *  **`unverified` is not a softer pass and must never look like one.** It is the one
 *  status that a reader most wants to skim past, and the one where doing so is
 *  expensive: a cell nobody could check, presented in the same family of greens as one
 *  that was checked, turns a coverage gap into a compliance claim.
 *
 *  So it gets the `unknown` tone — muted and dashed, visibly not a verdict — rather
 *  than an amber that reads as "mostly fine". `upheld` is the only success tone on this
 *  page.
 */
export const STATUS_LABELS: Record<CellStatus, { label: string; tone: string; meaning: string }> = {
  upheld: {
    label: 'Upheld',
    tone: 'success',
    meaning: 'The estate does what the policy says.',
  },
  violated: {
    label: 'Violated',
    tone: 'denied',
    meaning: 'The estate does something the policy forbids, or fails to do what it requires.',
  },
  unverified: {
    label: 'Not verified',
    tone: 'unknown',
    meaning:
      'The path could not be traced far enough to say anything either way. This is not a pass.',
  },
};
