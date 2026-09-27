/** Platform settings and notification channels (FR-ADM-01, FR-INT-01). */

export type ChannelKind = 'email' | 'webhook' | 'slack' | 'teams';

export interface NotificationChannel {
  id: string;
  name: string;
  channel_type: ChannelKind;
  enabled: boolean;
  config: Record<string, unknown>;
  /** Whether a secret is stored. The secret itself is never returned by the API. */
  has_secret: boolean;
  last_success_at: string | null;
  last_failure_at: string | null;
  last_error: string | null;
}

/** The events a person can be notified about, mirroring `integrations/events.py`.
 *
 *  `audit` is deliberately absent. It exists in the backend's vocabulary for the
 *  SIEM feed, which wants the whole audit trail — but FR-INT-01 notifies a *person*,
 *  and offering "every audit record" as something to be paged about would turn a
 *  login failure into an interruption. Subscribing to it is not a thing this form
 *  should make easy. */
export const EVENT_LABELS: Record<string, string> = {
  'job.completed': 'Assessment finished',
  'job.failed': 'Assessment failed',
  'finding.opened': 'New critical or high finding',
  'vuln.kev_matched': 'Known-exploited CVE matched',
  'drift.detected': 'Configuration drift',
  'device.identity_changed': 'Device identity changed',
  'credential.failed': 'Credential failed',
  'feed.sync_failed': 'Feed sync failed',
  'exception.expiring': 'Exception about to expire',
};

export interface NotificationSubscription {
  id: string;
  channel_id: string;
  event_kinds: string[];
  min_severity: string;
  enabled: boolean;
}

export type DeliveryStatus = 'queued' | 'sent' | 'retrying' | 'dead';

export interface NotificationDelivery {
  id: string;
  channel_id: string;
  event_kind: string;
  severity: string;
  title: string;
  status: DeliveryStatus;
  attempts: number;
  next_attempt_at: string | null;
  sent_at: string | null;
  last_error: string | null;
}

export interface PlatformSetting {
  key: string;
  value: Record<string, unknown>;
  description: string | null;
  /** Maintained by the product; the API refuses a write. */
  managed: boolean;
}

export const CHANNEL_LABELS: Record<ChannelKind, string> = {
  email: 'E-mail',
  webhook: 'Webhook',
  slack: 'Slack',
  teams: 'Microsoft Teams',
};

/** What each channel type needs in its sealed half, for the create form's hint. */
export const SECRET_HINTS: Record<ChannelKind, string> = {
  email: 'password — the SMTP account password',
  webhook: 'secret — the HMAC signing key the receiver verifies',
  slack: 'url — the incoming-webhook URL, which is itself a credential',
  teams: 'url — the incoming-webhook URL, which is itself a credential',
};

/** Delivery status to the shared severity palette.
 *
 * `dead` is mapped to the error colour rather than a muted one on purpose: a delivery
 * that gave up is an alert nobody received, which is the state this page exists to make
 * visible.
 */
export const STATUS_TONE: Record<DeliveryStatus, string> = {
  sent: 'success',
  queued: 'info',
  retrying: 'warn',
  dead: 'error',
};
