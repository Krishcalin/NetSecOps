/** The evidence behind a snapshot: every command issued, in order (FR-COL-03, SEC-09).
 *
 * The product's loudest claim is that it never writes to a device and that every command
 * it sends is recorded. Until this panel existed the record was real but unreadable —
 * four API operations with no page — so the claim could only be taken on trust. This is
 * the screen an assessor asks for, and the one that makes "read-only" checkable by the
 * customer rather than asserted by us.
 *
 * Three things it deliberately does not smooth over:
 *
 * - **A snapshot with no collection.** An uploaded configuration has no command log,
 *   which is different from a collection that issued nothing. Rendering both as an empty
 *   table would be the silent-emptiness failure this codebase keeps finding in itself.
 * - **A partial collection.** `partial` is why checks downstream say "Not evaluated", so
 *   it leads the panel rather than sitting in a tooltip.
 * - **A command that failed.** A failed artefact and a command that returned nothing
 *   look identical in a body of text and mean entirely different things.
 *
 * The unredacted original is a separate, explicit, per-artefact fetch, never a toggle
 * over text the browser already holds — same reasoning as `ConfigViewer`. It requires
 * `config:view_unredacted`, and the server writes an audit record before it answers, so
 * the warning here is a statement of what will happen, not a deterrent.
 */

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';

import { api } from '../../api/client';
import { useAuth } from '../auth/useAuth';
import type { Artifact, ArtifactDetail, Collection } from './types';

interface Props {
  /** The selected snapshot's collection, or null when it was uploaded rather than collected. */
  collectionId: string | null;
}

function duration(collection: Collection): string | null {
  if (!collection.started_at || !collection.finished_at) return null;
  const ms = Date.parse(collection.finished_at) - Date.parse(collection.started_at);
  if (!Number.isFinite(ms) || ms < 0) return null;
  return ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(1)} s`;
}

function bytes(size: number): string {
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
  return `${(size / (1024 * 1024)).toFixed(1)} MB`;
}

/** The expanded body of one artefact, redacted or — on request — original. */
function ArtifactBody({ artifact }: { artifact: Artifact }) {
  const { can } = useAuth();
  const [unredacted, setUnredacted] = useState(false);

  const mayViewOriginal = can('config:view_unredacted');

  const body = useQuery({
    queryKey: ['artifact', artifact.id, unredacted ? 'raw' : 'redacted'],
    queryFn: () =>
      api.get<ArtifactDetail>(
        unredacted ? `/artifacts/${artifact.id}/raw` : `/artifacts/${artifact.id}`,
      ),
  });

  return (
    <div className="evidence__body">
      <div className="evidence__body-toolbar">
        <span className={body.data?.redacted === false ? 'pill pill--warning' : 'pill'}>
          {body.data?.redacted === false ? 'original' : 'redacted'}
        </span>

        {/* The hash is of the *original* response in both modes, so an assessor can
            verify integrity without anyone viewing the secret. That is the whole
            reason it is on the redacted record at all. */}
        <span className="mono evidence__hash" title="SHA-256 of the original response">
          sha256 {artifact.sha256.slice(0, 16)}…
        </span>

        {mayViewOriginal &&
          (unredacted ? (
            <button
              type="button"
              className="button button--ghost button--small"
              onClick={() => setUnredacted(false)}
            >
              Hide the original
            </button>
          ) : (
            <button
              type="button"
              className="button button--ghost button--small"
              title="Viewing the original writes an audit record naming you and this command"
              onClick={() => setUnredacted(true)}
            >
              Show the original
            </button>
          ))}
      </div>

      {unredacted && (
        <div className="alert alert--warning" role="status">
          This is the unredacted response. Opening it was recorded in the audit log against
          your account, with the command that produced it.
        </div>
      )}

      {body.isLoading ? (
        <p className="page-loading">Loading…</p>
      ) : body.isError ? (
        <div className="alert alert--error" role="alert">
          {unredacted
            ? 'The original could not be read. It may have been purged by retention, or your permission to read it may have been withdrawn.'
            : 'This artefact could not be read.'}
        </div>
      ) : body.data?.response === '' ? (
        <p className="empty">
          The command ran and returned nothing. That is the device&rsquo;s answer, not a
          collection failure.
        </p>
      ) : (
        <pre className="evidence__pre">{body.data?.response}</pre>
      )}
    </div>
  );
}

export function EvidencePanel({ collectionId }: Props) {
  const [openId, setOpenId] = useState<string | null>(null);

  const collection = useQuery({
    queryKey: ['collection', collectionId],
    queryFn: () => api.get<Collection>(`/collections/${collectionId}`),
    enabled: collectionId !== null,
  });

  const artifacts = useQuery({
    queryKey: ['artifacts', collectionId],
    queryFn: () => api.get<Artifact[]>(`/collections/${collectionId}/artifacts`),
    enabled: collectionId !== null,
  });

  if (collectionId === null) {
    return (
      <section className="card">
        <h2 className="card__title">Evidence</h2>
        <p className="empty">
          This configuration was uploaded rather than collected, so there is no command log
          for it. Evidence exists only for snapshots this system collected itself.
        </p>
      </section>
    );
  }

  const rows = artifacts.data ?? [];
  const failed = rows.filter((row) => !row.succeeded).length;
  const elapsed = collection.data ? duration(collection.data) : null;

  return (
    <section className="card">
      <div className="card__header">
        <h2 className="card__title">Evidence</h2>
        {collection.data && (
          <span className="card__meta mono">
            {collection.data.adapter}
            {collection.data.adapter_version && ` ${collection.data.adapter_version}`}
            {elapsed && ` · ${elapsed}`}
          </span>
        )}
      </div>

      <p className="page__subtitle">
        Every command this system issued to the device, in the order it issued them. The
        allow-list decides what may appear here; nothing that writes to a device can.
      </p>

      {collection.data?.partial && (
        <div className="alert alert--warning" role="alert">
          <strong>This collection was partial.</strong>{' '}
          {collection.data.error_message ??
            'Some commands did not complete.'}{' '}
          Checks that needed the missing output report Not Evaluated rather than passing.
        </div>
      )}

      {collection.isError && (
        <div className="alert alert--error" role="alert">
          The collection record could not be read.
        </div>
      )}

      {artifacts.isLoading ? (
        <p className="page-loading">Loading…</p>
      ) : rows.length === 0 ? (
        <p className="empty">
          This collection recorded no commands. That is itself unexpected — a collection
          that produced a snapshot must have issued something — and is worth raising.
        </p>
      ) : (
        <>
          <p className="evidence__summary">
            {rows.length} command{rows.length === 1 ? '' : 's'}
            {failed > 0 && (
              <>
                , <strong>{failed} of which failed</strong>
              </>
            )}
            .
          </p>

          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th className="evidence__ordinal">#</th>
                  <th>Command</th>
                  <th>Result</th>
                  <th>Size</th>
                  <th>Took</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => (
                  <tr key={row.id} className={openId === row.id ? 'table__row--active' : ''}>
                    <td className="mono evidence__ordinal">{row.ordinal}</td>
                    <td className="mono">{row.request_text}</td>
                    <td>
                      {row.succeeded ? (
                        <span className="pill pill--success">ok</span>
                      ) : (
                        <span
                          className="pill pill--failure"
                          title="The device rejected or failed this command"
                        >
                          failed
                        </span>
                      )}
                    </td>
                    <td className="mono">{bytes(row.size_bytes)}</td>
                    <td className="mono">{row.duration_ms == null ? '—' : `${row.duration_ms} ms`}</td>
                    <td className="table__actions">
                      <button
                        type="button"
                        className="button button--ghost button--small"
                        aria-expanded={openId === row.id}
                        onClick={() => setOpenId((current) => (current === row.id ? null : row.id))}
                      >
                        {openId === row.id ? 'Hide' : 'View output'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {openId !== null && (
            <ArtifactBody artifact={rows.find((row) => row.id === openId) as Artifact} />
          )}
        </>
      )}
    </section>
  );
}
