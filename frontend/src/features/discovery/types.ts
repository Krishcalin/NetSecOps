/** Discovery types, mirroring netsecops/schemas/discovery.py. */

export type HostStatus = 'pending' | 'approved' | 'rejected' | 'onboarded';

export interface DiscoveryScope {
  id: string;
  name: string;
  description: string | null;
  targets: string[];
  exclusions: string[];
  tcp_ports: number[];
  rate_limit_per_second: number;
  snmp_configured: boolean;
  auto_onboard: boolean;
  enabled: boolean;
  created_at: string | null;
  /** Addresses remaining once exclusions are subtracted. Null when a stored scope no
   *  longer validates under current rules — readable so it can be corrected. */
  address_count: number | null;
}

export interface DiscoveryRun {
  id: string;
  scope_id: string;
  status: string;
  started_at: string;
  finished_at: string | null;
  addresses_probed: number;
  hosts_found: number;
  hosts_unidentified: number;
  error_message: string | null;
}

export interface DiscoveredHost {
  id: string;
  address: string;
  run_id: string | null;
  status: HostStatus;
  vendor: string | null;
  platform: string | null;
  hostname: string | null;
  /** 0-100. Low means "could not tell", not "probably not a device" — which is why the
   *  queue opens with the lowest. */
  confidence: number;
  fingerprint: Record<string, unknown>;
  device_id: string | null;
  first_seen_at: string | null;
  last_seen_at: string | null;
  reviewed_at: string | null;
  review_note: string | null;
}

/** The evidence keys the fingerprinter records, with readable names. */
export const SIGNAL_LABELS: Record<string, string> = {
  ssh_banner: 'SSH banner',
  tls_subject: 'TLS certificate subject',
  tls_issuer: 'TLS certificate issuer',
  http_header: 'HTTP header',
  http_marker: 'Login page marker',
  snmp_sysobjectid: 'SNMP sysObjectID',
  snmp_sysdescr: 'SNMP sysDescr',
};

export function confidenceBand(confidence: number): 'low' | 'medium' | 'high' {
  if (confidence >= 70) return 'high';
  if (confidence >= 40) return 'medium';
  return 'low';
}
