/** Snapshot, diff and drift types, mirroring netsecops/schemas/snapshots.py.
 *
 * Hand-written for now, like the inventory types; `npm run gen:api` regenerates them
 * from the published OpenAPI document once the API is running.
 */

export interface Snapshot {
  id: string;
  device_id: string;
  collection_id: string | null;
  config_hash: string;
  normalized_hash: string;
  ncm_version: string;
  parser_platform: string | null;
  /** How much of the configuration the parser understood, as a percentage. */
  parse_coverage: number | null;
  unparsed_count: number;
  is_baseline: boolean;
  baseline_pinned_at: string | null;
  seen_count: number;
  last_seen_at: string | null;
  created_at: string;
}

export interface SnapshotDetail extends Snapshot {
  /** The configuration with secrets replaced by placeholders (FR-COL-13). */
  config_redacted: string;
  ncm: Record<string, unknown>;
}

export interface SemanticChange {
  path: string;
  description: string;
}

export interface ConfigDiff {
  from_snapshot_id: string;
  to_snapshot_id: string;
  changed: boolean;
  added: string[];
  removed: string[];
  unified: string;
  before_lines: string[];
  after_lines: string[];
  semantic: SemanticChange[];
}

export interface Drift {
  device_id: string;
  baseline_snapshot_id: string | null;
  latest_snapshot_id: string | null;
  changed: boolean;
  severity: string | null;
  headline: string;
  added: string[];
  removed: string[];
  semantic: SemanticChange[];
  finding_id: string | null;
}

export interface Artifact {
  id: string;
  collection_id: string;
  kind: string;
  request_text: string;
  sha256: string;
  size_bytes: number;
  duration_ms: number | null;
  ordinal: number;
  succeeded: boolean;
  created_at: string;
}

export interface ArtifactDetail extends Artifact {
  response: string;
  redacted: boolean;
}

export interface ConfigUploadResponse {
  snapshot_id: string;
  collection_id: string;
  artifact_id: string;
  deduplicated: boolean;
  parse_coverage: number | null;
  unparsed_count: number;
  drift: Drift;
}
