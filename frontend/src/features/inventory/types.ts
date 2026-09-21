/** Inventory and job types mirroring the backend Pydantic schemas.
 *
 * Hand-written for now; `npm run gen:api` regenerates them from the published OpenAPI
 * document once the API is running, so the two cannot drift for long.
 */

export type Vendor = 'cisco' | 'paloalto' | 'fortinet' | 'checkpoint' | 'linux' | 'unknown';

export type DeviceClass =
  | 'firewall'
  | 'switch'
  | 'router'
  | 'wireless_ap'
  | 'wireless_controller'
  | 'manager'
  | 'aaa_server'
  | 'unknown';

export type Criticality = 'critical' | 'high' | 'medium' | 'low';
export type DeviceStatus = 'active' | 'archived' | 'pending_review';

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
  unknown: 'Unknown',
};

export const CRITICALITY_ORDER: Criticality[] = ['critical', 'high', 'medium', 'low'];
