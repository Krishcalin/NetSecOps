/** Writing the policy the matrix is judged against (FR-TOPO-07).
 *
 * The matrix above this is the product's answer to "is what the estate does what we
 * said it would do". Until this existed, the second half of that sentence could only be
 * written through the API — so on any deployment whose operators use the console, the
 * page evaluated a policy nobody could author and read as permanently empty. An empty
 * matrix is not a clean one, and the page said so; it just gave nobody a way out.
 *
 * **A zone is address space, not a firewall's zone name.** `dmz` on one device and
 * `DMZ` on another may be different things and a router has no zone names at all, so
 * the form asks for CIDRs. That is the one piece of typing this feature cannot avoid,
 * and the reason is worth stating on the form rather than in a manual.
 *
 * **Removing a zone is refused while any intent names it.** Both foreign keys cascade,
 * so the database would take the zone and every statement mentioning it — one tidy-up
 * silently withdrawing a dozen requirements. The button says how many intents stand in
 * the way instead of offering an action that quietly does more than it says.
 *
 * **Every change invalidates the matrix.** A new intent that did not appear in the
 * verdicts above would read as a page that had not saved it.
 */

import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { ApiError, api } from '../../api/client';
import { useAuth } from '../auth/useAuth';
import { MIN_JUSTIFICATION } from './types';
import type { Expectation, IntentRule, Zone } from './types';

/** CIDRs as people type them: one per line, or comma-separated, or both. */
function parsePrefixes(text: string): string[] {
  return text
    .split(/[\s,]+/)
    .map((part) => part.trim())
    .filter(Boolean);
}

function message(error: unknown, fallback: string): string {
  return error instanceof ApiError ? error.problem.detail : fallback;
}

export function PolicyEditor() {
  const { can } = useAuth();
  const queryClient = useQueryClient();
  const canWrite = can('policy:write');

  const [error, setError] = useState<string | null>(null);
  const [zoneName, setZoneName] = useState('');
  const [zonePrefixes, setZonePrefixes] = useState('');
  const [zoneDescription, setZoneDescription] = useState('');

  const [source, setSource] = useState('');
  const [destination, setDestination] = useState('');
  const [expectation, setExpectation] = useState<Expectation>('denied');
  const [protocol, setProtocol] = useState('tcp');
  const [port, setPort] = useState(443);
  const [justification, setJustification] = useState('');

  const zones = useQuery({
    queryKey: ['segmentation-zones'],
    queryFn: () => api.get<Zone[]>('/segmentation/zones'),
  });
  const rules = useQuery({
    queryKey: ['segmentation-rules'],
    queryFn: () => api.get<IntentRule[]>('/segmentation/rules'),
  });

  // The matrix is invalidated by every one of these, not only the intent ones: a zone's
  // prefixes are what each cell is walked over, so adding or removing one changes what
  // the verdicts above mean.
  const refresh = () => {
    setError(null);
    for (const key of ['segmentation-zones', 'segmentation-rules', 'segmentation-matrix']) {
      void queryClient.invalidateQueries({ queryKey: [key] });
    }
  };

  const createZone = useMutation({
    mutationFn: () =>
      api.post<Zone>('/segmentation/zones', {
        name: zoneName.trim(),
        prefixes: parsePrefixes(zonePrefixes),
        description: zoneDescription.trim() || null,
      }),
    onSuccess: () => {
      setZoneName('');
      setZonePrefixes('');
      setZoneDescription('');
      refresh();
    },
    onError: (err) => setError(message(err, 'The zone could not be declared.')),
  });

  const removeZone = useMutation({
    mutationFn: (id: string) => api.delete<void>(`/segmentation/zones/${id}`),
    onSuccess: refresh,
    onError: (err) => setError(message(err, 'The zone could not be removed.')),
  });

  const createRule = useMutation({
    mutationFn: () =>
      api.post<IntentRule>('/segmentation/rules', {
        source_zone_id: source,
        destination_zone_id: destination,
        expectation,
        protocol,
        port,
        justification: justification.trim(),
      }),
    onSuccess: () => {
      setJustification('');
      refresh();
    },
    onError: (err) => setError(message(err, 'The intent could not be declared.')),
  });

  const zoneList = zones.data ?? [];
  const ruleList = rules.data ?? [];

  const referenceCount = (id: string) =>
    ruleList.filter((rule) => rule.source_zone_id === id || rule.destination_zone_id === id).length;

  const zoneReady = zoneName.trim().length > 0 && parsePrefixes(zonePrefixes).length > 0;
  const ruleReady =
    source !== '' &&
    destination !== '' &&
    source !== destination &&
    justification.trim().length >= MIN_JUSTIFICATION;

  return (
    <section className="card">
      <div className="card__header">
        <h2 className="card__title">The policy</h2>
      </div>
      <p className="finding__note">
        What the matrix above is judged against. A zone is a named piece of address space —
        deliberately not a firewall&rsquo;s zone name, because <span className="mono">dmz</span> on
        one device and <span className="mono">DMZ</span> on another may be different things, and a
        router has none at all. The addresses are what a packet can actually be traced over.
      </p>

      {error && (
        <div className="alert alert--error" role="alert">
          {error}
        </div>
      )}

      <h3 className="finding__heading">Zones</h3>
      {zoneList.length === 0 ? (
        <p className="empty">
          No zones yet. Declare two — the pair you most need to keep apart — and then state what
          should happen between them.
        </p>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <caption className="visually-hidden">
              Declared zones and the address space of each
            </caption>
            <thead>
              <tr>
                <th>Zone</th>
                <th>Address space</th>
                <th>Named by</th>
                {canWrite && <th>Remove</th>}
              </tr>
            </thead>
            <tbody>
              {zoneList.map((zone) => {
                const used = referenceCount(zone.id);
                return (
                  <tr key={zone.id}>
                    <td>
                      {zone.name}
                      {zone.description && (
                        <span className="finding__note"> {zone.description}</span>
                      )}
                    </td>
                    <td className="mono">{zone.prefixes.join(', ')}</td>
                    <td>
                      {used === 0 ? (
                        <span className="finding__note">no intent</span>
                      ) : (
                        `${used} intent${used === 1 ? '' : 's'}`
                      )}
                    </td>
                    {canWrite && (
                      <td>
                        {/* Disabled rather than hidden, with the count as the reason.
                            A button that silently withdrew every statement about the
                            zone would do far more than it said. */}
                        <button
                          className="button button--ghost button--small"
                          disabled={used > 0 || removeZone.isPending}
                          title={
                            used > 0
                              ? `Withdraw the ${used} intent(s) naming this zone first`
                              : undefined
                          }
                          onClick={() => removeZone.mutate(zone.id)}
                        >
                          Remove
                        </button>
                      </td>
                    )}
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {canWrite && (
        <>
          <h3 className="finding__heading">Declare a zone</h3>
          <div className="form-grid">
            <label className="field">
              <span className="field__label">Name</span>
              <input
                id="zone-name"
                className="field__input"
                value={zoneName}
                placeholder="Cardholder data"
                onChange={(event) => setZoneName(event.target.value)}
              />
            </label>
            <label className="field">
              <span className="field__label">Address space</span>
              <textarea
                id="zone-prefixes"
                className="field__input"
                // Named explicitly because the hint below sits inside the label: without
                // this the field's accessible *name* becomes the label plus the whole
                // sentence of guidance, which is how it is announced on every visit.
                aria-label="Address space"
                rows={2}
                value={zonePrefixes}
                placeholder="10.20.0.0/24, 10.21.0.0/24"
                onChange={(event) => setZonePrefixes(event.target.value)}
              />
              <span className="field__help">
                CIDRs, separated by commas or newlines. Every one of them is walked when a rule
                touching this zone is checked.
              </span>
            </label>
            <label className="field">
              <span className="field__label">Description (optional)</span>
              <input
                id="zone-description"
                className="field__input"
                value={zoneDescription}
                onChange={(event) => setZoneDescription(event.target.value)}
              />
            </label>
          </div>
          <div className="finding__actions">
            <button
              className="button"
              disabled={!zoneReady || createZone.isPending}
              onClick={() => createZone.mutate()}
            >
              {createZone.isPending ? 'Declaring…' : 'Declare zone'}
            </button>
          </div>

          <h3 className="finding__heading">Declare an intent</h3>
          {zoneList.length < 2 ? (
            <p className="empty">
              An intent is about an ordered pair of zones, so there have to be two. Declare another
              zone above.
            </p>
          ) : (
            <>
              <p className="finding__note">
                Ordered, because &ldquo;A may reach B&rdquo; says nothing about the reverse — most
                real segmentation is asymmetric, and a web tier reaching a database tier is normal
                while the reverse is an incident. Each statement names one protocol and port,
                because that is what a packet trace evaluates.
              </p>
              <div className="form-grid">
                <label className="field">
                  <span className="field__label">From</span>
                  <select
                    id="intent-source"
                    className="field__input"
                    value={source}
                    onChange={(event) => setSource(event.target.value)}
                  >
                    <option value="">Choose a zone</option>
                    {zoneList.map((zone) => (
                      <option key={zone.id} value={zone.id}>
                        {zone.name}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="field">
                  <span className="field__label">To</span>
                  <select
                    id="intent-destination"
                    className="field__input"
                    value={destination}
                    onChange={(event) => setDestination(event.target.value)}
                  >
                    <option value="">Choose a zone</option>
                    {zoneList.map((zone) => (
                      <option key={zone.id} value={zone.id}>
                        {zone.name}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="field">
                  <span className="field__label">Should be</span>
                  <select
                    id="intent-expectation"
                    className="field__input"
                    value={expectation}
                    onChange={(event) => setExpectation(event.target.value as Expectation)}
                  >
                    <option value="denied">denied</option>
                    <option value="allowed">allowed</option>
                  </select>
                </label>
                <label className="field">
                  <span className="field__label">Protocol</span>
                  <select
                    id="intent-protocol"
                    className="field__input"
                    value={protocol}
                    onChange={(event) => setProtocol(event.target.value)}
                  >
                    {['tcp', 'udp', 'icmp'].map((value) => (
                      <option key={value} value={value}>
                        {value}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="field">
                  <span className="field__label">Port</span>
                  <input
                    id="intent-port"
                    className="field__input"
                    type="number"
                    value={port}
                    onChange={(event) => setPort(Number(event.target.value))}
                  />
                </label>
                <label className="field">
                  <span className="field__label">Why this rule exists</span>
                  <textarea
                    id="intent-justification"
                    className="field__input"
                    aria-label="Why this rule exists"
                    rows={2}
                    value={justification}
                    placeholder="PCI DSS 1.2.1 — the CDE is not reachable from the general estate."
                    onChange={(event) => setJustification(event.target.value)}
                  />
                  {/* Required by the API, and said here rather than discovered from a
                      422 after the field has scrolled away. A matrix cell nobody can
                      explain is one nobody dares change. */}
                  <span className="field__help">
                    Required, and at least {MIN_JUSTIFICATION} characters. It appears beside the
                    verdict, so it is what a later reader has to go on.
                  </span>
                </label>
              </div>

              {source !== '' && source === destination && (
                <p className="finding__note">
                  A zone cannot be segmented from itself — traffic inside one crosses no boundary,
                  so there would be nothing to trace.
                </p>
              )}

              <div className="finding__actions">
                <button
                  className="button"
                  disabled={!ruleReady || createRule.isPending}
                  onClick={() => createRule.mutate()}
                >
                  {createRule.isPending ? 'Declaring…' : 'Declare intent'}
                </button>
              </div>
            </>
          )}
        </>
      )}

      {!canWrite && (
        <p className="finding__note">
          Declaring and withdrawing policy needs <span className="mono">policy:write</span>. The
          matrix above is readable without it — reading what the estate does and stating what it
          should do are deliberately different permissions.
        </p>
      )}
    </section>
  );
}
