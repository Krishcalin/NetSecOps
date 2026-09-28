/** Inventory and job types mirroring the backend Pydantic schemas.
 *
 * Hand-written for now; `npm run gen:api` regenerates them from the published OpenAPI
 * document once the API is running, so the two cannot drift for long.
 */

export const VENDORS = [
  'cisco',
  'paloalto',
  'fortinet',
  'checkpoint',
  'linux',
  'radware',
  'barracuda',
  'unknown',
] as const;

export type Vendor = (typeof VENDORS)[number];

/** The device classes the product recognises (SRS §1.3, §1.3.1).
 *
 * One vocabulary, and the type is derived from it rather than written twice. It was in
 * four places when `load_balancer` and `waf` were added — this union, the Inventory
 * page's picker, the Risk Trends page's picker, and a label map beside each — which is
 * four chances for a class the backend accepts to be missing from a control. A filter
 * whose options are a subset of reality is a filter that lies about the estate.
 *
 * `deviceClasses.test.ts` reads the `DeviceClass` enum out of the backend model and
 * fails if the two disagree, which is the check that actually protects this: a class
 * added to the server and not here is capability with no surface, and on a
 * console-only deployment that is indistinguishable from capability that is absent.
 *
 * The order is the one the pickers show — the three appliance types the sidebar names
 * first, then the rest, then whatever is still unclassified.
 */
export const DEVICE_CLASSES = [
  'router',
  'switch',
  'firewall',
  'wireless_controller',
  'wireless_ap',
  'load_balancer',
  'waf',
  'manager',
  'aaa_server',
  'unknown',
] as const;

export type DeviceClass = (typeof DEVICE_CLASSES)[number];

/** Plural, for a filter option and the heading it produces — "Firewalls by grade". */
export const CLASS_LABELS: Record<string, string> = {
  router: 'Routers',
  switch: 'Switches',
  firewall: 'Firewalls',
  wireless_controller: 'Wireless controllers',
  wireless_ap: 'Wireless access points',
  load_balancer: 'Load balancers',
  waf: 'Web application firewalls',
  manager: 'Managers',
  aaa_server: 'AAA servers',
  unknown: 'Unclassified',
};

/** Singular, for a row, which describes one device.
 *
 * A second map rather than trimming an `s`: three of these do not pluralise that way,
 * and `AAA server` and `Wireless AP` carry capitals a `text-transform` would either
 * flatten or over-apply.
 */
export const CLASS_SINGULAR: Record<string, string> = {
  router: 'Router',
  switch: 'Switch',
  firewall: 'Firewall',
  wireless_controller: 'Wireless controller',
  wireless_ap: 'Wireless AP',
  load_balancer: 'Load balancer',
  waf: 'Web application firewall',
  manager: 'Manager',
  aaa_server: 'AAA server',
  unknown: 'Unclassified',
};

/** A class the maps have never heard of falls back to its own key rather than to
 *  nothing: an unlabelled row reads as a loading failure, where the key at least says
 *  the console is behind its server. */
export function classLabel(value: string, form: 'plural' | 'singular' = 'singular'): string {
  const map = form === 'plural' ? CLASS_LABELS : CLASS_SINGULAR;
  return map[value] ?? value;
}

export type Criticality = 'critical' | 'high' | 'medium' | 'low';

export const DEVICE_STATUSES = [
  'active',
  'pending_review',
  'inventory_only',
  'archived',
] as const;

export type DeviceStatus = (typeof DEVICE_STATUSES)[number];

/** What a status means in the inventory, and how loudly to say it.
 *
 * Every one of these is a different reason a device has never been collected from, and
 * the column exists because otherwise all four produce the same blank "last collected"
 * cell. A status the console cannot name falls through to whatever the last branch is,
 * which is how `inventory_only` briefly rendered as "active" — an access point that
 * is deliberately never assessed, reported as a device under assessment.
 *
 * `null` for `active`, which needs no pill: it is the ordinary case and a badge on
 * every row is a badge nobody reads.
 */
export const STATUS_PILLS: Record<DeviceStatus, { label: string; tone: string } | null> = {
  active: null,
  pending_review: { label: 'awaiting approval', tone: 'medium' },
  // Not "not assessed", which reads as an omission. This is a deliberate exclusion:
  // a CAPWAP access point holds no configuration, so there is nothing to collect and
  // no approval that would change it.
  inventory_only: { label: 'inventory only', tone: 'info' },
  archived: { label: 'archived', tone: 'unknown' },
};

export interface Device {
  id: string;
  mgmt_ip: string;
  hostname: string | null;
  fqdn: string | null;
  vendor: Vendor;
  platform: string | null;
  device_class: DeviceClass;
  criticality: Criticality;
  status: DeviceStatus;
  site_id: string | null;
  parent_device_id: string | null;
  /** What the parent is called. The id alone is a UUID, which is why it shipped in
   *  Phase 1 and nothing rendered it for three phases. */
  parent_hostname: string | null;
  /** So the console can say "served by" for a controller and "managed by" for a
   *  Panorama — both are `parent_device_id` and they are different relationships. */
  parent_device_class: string | null;
  /** How many devices name this one as their parent. Nought for almost everything. */
  child_count: number;
  serial_number: string | null;
  os_version: string | null;
  model: string | null;
  facts: Record<string, unknown>;
  last_collected_at: string | null;
  last_seen_at: string | null;
  host_key_fingerprint: string | null;
  ssh_port: number;
  https_port: number;
  allow_expert: boolean;
  allow_sudo_read: boolean;
  notes: string | null;
  created_at: string;
  updated_at: string;
}

/** A device imported from a manager and not yet admitted to assessment (FR-INV-04).
 *
 * It is already in inventory and excluded from every job, so nothing has connected to it.
 * Approving is the act that admits it — which is why the manager's own attribution is
 * carried here rather than only the identity: somebody has to judge whether this is a
 * device they meant to start reaching for. */
export interface PendingDevice {
  id: string;
  hostname: string | null;
  mgmt_ip: string;
  vendor: string;
  platform: string | null;
  device_class: string;
  serial_number: string | null;
  model: string | null;
  os_version: string | null;
  parent_device_id: string | null;
  facts: Record<string, unknown>;
}

export interface DeviceDetail extends Device {
  group_ids: string[];
  tags: string[];
  credential_names: string[];
}

export interface DeviceGroup {
  id: string;
  name: string;
  description: string | null;
  parent_id: string | null;
  path: string;
  created_at: string;
}

export interface Site {
  id: string;
  name: string;
  description: string | null;
  location: string | null;
}

export interface Credential {
  id: string;
  name: string;
  description: string | null;
  credential_type: string;
  metadata: Record<string, unknown>;
  key_id: string;
  last_used_at: string | null;
  last_tested_at: string | null;
  last_test_succeeded: boolean | null;
  created_at: string;
}

export interface CredentialTestResult {
  succeeded: boolean;
  device_id: string;
  detail: string | null;
  /** The single read command that was issued — shown so operators see what ran. */
  command: string | null;
  host_key_fingerprint: string | null;
}

export type JobStatus =
  'queued' | 'running' | 'paused' | 'cancelling' | 'cancelled' | 'succeeded' | 'partial' | 'failed';

export interface Job {
  id: string;
  job_type: string;
  status: JobStatus;
  scope: Record<string, unknown>;
  stats: Record<string, number>;
  requested_by_id: string | null;
  started_at: string | null;
  finished_at: string | null;
  error_message: string | null;
  created_at: string;
}

export interface JobDeviceResult {
  id: string;
  device_id: string;
  status: string;
  error_class: string | null;
  error_message: string | null;
  duration_ms: number | null;
  command_count: number;
}

export interface JobDetail extends Job {
  devices: JobDeviceResult[];
}

export interface Paginated<T> {
  data: T[];
  meta: { total: number; limit: number; offset: number };
}

export interface ImportRowResult {
  line: number;
  valid: boolean;
  action: 'create' | 'update' | 'error';
  errors: string[];
  mgmt_ip: string | null;
}

export interface ImportPreview {
  ok: boolean;
  creates: number;
  updates: number;
  invalid: number;
  rows: ImportRowResult[];
}

export const VENDOR_LABELS: Record<Vendor, string> = {
  cisco: 'Cisco',
  paloalto: 'Palo Alto',
  fortinet: 'Fortinet',
  checkpoint: 'Check Point',
  linux: 'Linux',
  radware: 'Radware',
  barracuda: 'Barracuda',
  unknown: 'Unknown',
};

export const CRITICALITY_ORDER: Criticality[] = ['critical', 'high', 'medium', 'low'];
