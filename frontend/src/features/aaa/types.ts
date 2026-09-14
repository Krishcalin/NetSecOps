/** AAA posture types (FR-AAA-05, FR-AAA-06).
 *
 * Mirrors `netsecops/schemas/aaa.py`. Three fields are nullable on purpose and each
 * would do damage if the UI collapsed the null into a value:
 *
 * `coverage_percentage` is `null` when no device could be assessed. Rendering that as
 * 0% sends someone to roll out TACACS+ across an estate nobody has collected from.
 *
 * `days_remaining` is `null` when the expiry date could not be interpreted. The
 * certificate is still on the timeline — an unreadable date is not a distant one — but
 * it must not be sorted or bucketed as though it had a date.
 *
 * `admin_mfa_enabled` is `null` where the product has no such concept. FreeRADIUS and
 * tac_plus never report it, and showing "no" would invent a finding on every
 * open-source AAA server in the estate.
 */

export interface Protocol {
  name: string;
  /** PAP, CHAP, MS-CHAPv1, EAP-MD5, LEAP — a finding regardless of context. */
  weak: boolean;
  servers: string[];
}

export interface Transport {
  kind: string;
  devices: number;
}

export interface CertificateEntry {
  device_id: string;
  device: string;
  name: string | null;
  subject: string | null;
  issuer: string | null;
  self_signed: boolean | null;
  usage: string[];
  /** ISO-8601, or null when the source date could not be read. */
  expires_at: string | null;
  days_remaining: number | null;
}

export interface CertificateTimeline {
  entries: CertificateEntry[];
  total: number;
  expired: number;
  expiring_soon: number;
  expiring_within_horizon: number;
  /** Certificates on the timeline with no readable date. Counted, never dropped. */
  undated: number;
  /** AAA servers that contributed no certificate — where the timeline is blind. */
  servers_without_certificates: string[];
  soon_days: number;
  horizon_days: number;
}

export interface AaaServer {
  device_id: string;
  hostname: string | null;
  product: string | null;
  clients: number;
  identity_stores: number;
  weak_protocols: string[];
  admin_mfa_enabled: boolean | null;
  snapshot_age_days: number | null;
  certificates: number;
}

export interface OrphanedClient {
  name: string;
  address: string | null;
  server: string;
  server_device_id: string;
  server_snapshot_age_days: number | null;
}

export interface UnregisteredDevice {
  device_id: string;
  hostname: string | null;
  mgmt_ip: string;
  configured_for_aaa: boolean;
}

export interface UnknownServer {
  address: string;
  kind: string;
  used_by: string[];
}

export interface SecretReuse {
  fingerprint: string;
  used_by: string[];
  clients: number;
}

export interface Correlation {
  orphaned_clients: OrphanedClient[];
  unregistered_devices: UnregisteredDevice[];
  unknown_servers: UnknownServer[];
  reused_secrets: SecretReuse[];
  servers_examined: number;
  /** Clients whose server masks the secret: reuse is *unknown*, not absent. */
  secrets_not_exposable: number;
  /** False when no AAA server was collected from. While false, the unregistered list
   *  is not a conclusion and must not be presented as one. */
  registration_analysed: boolean;
}

export interface AaaPosture {
  coverage_percentage: number | null;
  devices_total: number;
  devices_with_central_auth: number;
  devices_not_evaluated: number;
  accepted_protocols: Protocol[];
  transports: Transport[];
  servers: AaaServer[];
  certificates: CertificateTimeline;
  correlation: Correlation;
  open_findings: Record<string, number>;
  limitations: string[];
  generated_at: string;
}

/** How a certificate should read on the timeline.
 *
 * `undated` is deliberately its own state rather than folding into `ok`. A certificate
 * with an unreadable date is not one that is fine; it is one nobody has checked.
 */
export type CertificateState = 'expired' | 'urgent' | 'soon' | 'ok' | 'undated';

export function certificateState(
  entry: CertificateEntry,
  timeline: Pick<CertificateTimeline, 'soon_days' | 'horizon_days'>,
): CertificateState {
  if (entry.days_remaining === null) return 'undated';
  if (entry.days_remaining < 0) return 'expired';
  if (entry.days_remaining <= timeline.soon_days) return 'urgent';
  if (entry.days_remaining <= timeline.horizon_days) return 'soon';
  return 'ok';
}

export function describeRemaining(entry: CertificateEntry): string {
  if (entry.days_remaining === null) return 'no readable expiry date';
  if (entry.days_remaining < 0) {
    const days = Math.abs(entry.days_remaining);
    return `expired ${days} day${days === 1 ? '' : 's'} ago`;
  }
  if (entry.days_remaining === 0) return 'expires today';
  return `${entry.days_remaining} day${entry.days_remaining === 1 ? '' : 's'} left`;
}

/** Three states, kept distinct. `null` is "the product does not report this". */
export function describeTriState(value: boolean | null): string {
  if (value === null) return 'unknown';
  return value ? 'yes' : 'no';
}
