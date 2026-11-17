import { useEffect, useRef, useState } from 'react';

import { ApiError, getEvent, type EventDocument } from '../lib/api';
import { useAsync } from '../lib/useAsync';
import { Drawer } from './Drawer';
import { LoadingInline, Spinner } from './States';

// ---------------------------------------------------------------------------
// One document from the grid, as the sensor wrote it.
//
// An evidence id is the proof an analytic works. Every surface that held one
// — the shadow-hit receipts, the lead timeline, a finding's citations — showed
// it as a dashed chip that did nothing, beside a comment saying the app had no
// document viewer. So the one thing that settles "did this analytic match the
// right thing" was the one thing an analyst could not read.
//
// The source is flattened to dotted keys and sorted. A raw JSON blob answers
// "what is in this document" only for the person who already knows the schema.
// ---------------------------------------------------------------------------

const NOT_FOUND = 'The grid holds no document with this id. It may have aged out.';

/** An empty id is not a document that aged out. A finding that cites nothing
 *  opened the drawer on an empty id, and the drawer blamed the grid. */
const NO_ID = 'No document id was given.';

const READ_FAILED = 'Could not read the document.';

export const DOCUMENT_TITLE =
  'This is an Elasticsearch document id. Open it to read the document.';

/** One value, as one line. An array is joined, because one key with four rows
 *  under it reads as four separate facts. */
function scalar(value: unknown): string {
  if (value === null || value === undefined) return '';
  if (typeof value === 'object') return JSON.stringify(value);
  return String(value);
}

function walk(value: unknown, prefix: string, out: Array<[string, string]>): void {
  if (Array.isArray(value)) {
    out.push([prefix, value.map(scalar).join(', ')]);
    return;
  }
  if (value !== null && typeof value === 'object') {
    for (const [key, inner] of Object.entries(value as Record<string, unknown>)) {
      walk(inner, prefix ? `${prefix}.${key}` : key, out);
    }
    return;
  }
  out.push([prefix, scalar(value)]);
}

/** The source object as dotted key and value pairs, sorted by key. */
export function flattenSource(
  source: Record<string, unknown> | null | undefined,
): Array<[string, string]> {
  const out: Array<[string, string]> = [];
  walk(source ?? {}, '', out);
  return out.filter(([key]) => key !== '').sort((a, b) => a[0].localeCompare(b[0]));
}

function CopyJson({ source }: { source: Record<string, unknown> }) {
  const [copied, setCopied] = useState(false);
  // The clipboard API is undefined in an insecure context, and a plain-http
  // LAN install would otherwise get a button that silently does nothing.
  const canCopy = typeof navigator !== 'undefined' && !!navigator.clipboard;
  if (!canCopy) return null;
  return (
    <button
      type="button"
      className="rounded-control border border-border-strong px-2 py-0.5 text-[11px] font-semibold"
      onClick={() => {
        navigator.clipboard
          .writeText(JSON.stringify(source, null, 2))
          .then(() => {
            setCopied(true);
            window.setTimeout(() => setCopied(false), 1500);
          })
          .catch(() => {});
      }}
    >
      {copied ? 'Copied' : 'Copy JSON'}
    </button>
  );
}

/** A field that a report cites, for the drawer to show first. `label` is
 *  the field in words, `path` the raw path the model wrote, and `value` the
 *  value the run read. `valueTruncated` is true when the server cut the
 *  value at 2,000 characters. */
export interface CitedField {
  label: string;
  path: string;
  value: string | null;
  valueTruncated?: boolean;
}

/** The line under a cited value that the server cut. */
export const CITED_VALUE_CUT = 'The value is cut at 2,000 characters.';

/** The rows of the document that hold the cited field: a key with the same
 *  leaf, or the same value. The run stores a field under its own name, and
 *  the grid can name it another way (`zeek_http_status`, `http.status_code`). */
export function citedRows(rows: Array<[string, string]>, cited: CitedField): Set<string> {
  const leaf = cited.path.split('.').filter((p) => !/^\d+$/.test(p)).pop() ?? '';
  const value = (cited.value ?? '').trim();
  const out = new Set<string>();
  for (const [key, v] of rows) {
    const keyLeaf = key.split('.').pop() ?? '';
    if ((leaf && keyLeaf === leaf) || (value !== '' && v.trim() === value)) out.add(key);
  }
  return out;
}

function CitedBlock({ cited }: { cited: CitedField }) {
  return (
    <div
      data-testid="document-cited"
      className="mt-3 rounded-card border border-accent/40 bg-accent/[.06] px-3 py-2"
    >
      <div className="text-[11px] text-faint">
        The report cites this field: <span className="font-semibold text-text-2">{cited.label}</span>
      </div>
      <div className="mt-0.5 break-all font-mono text-[11px] text-faint">{cited.path}</div>
      {cited.value != null && cited.value !== '' ? (
        <div
          data-testid="document-cited-value"
          className="mt-1.5 max-h-[240px] overflow-auto whitespace-pre-wrap break-all font-mono text-[11.5px] text-text-2"
        >
          {cited.value}
        </div>
      ) : (
        <div className="mt-1.5 text-[11.5px] text-dim">soc-ai stored no value for this field.</div>
      )}
      {cited.value != null && cited.value !== '' && cited.valueTruncated && (
        <div data-testid="document-cited-cut" className="mt-1 text-[11px] text-dim">
          {CITED_VALUE_CUT}
        </div>
      )}
    </div>
  );
}

function Body({ doc, cited }: { doc: EventDocument; cited?: CitedField }) {
  const rows = flattenSource(doc.source);
  const marked = cited ? citedRows(rows, cited) : new Set<string>();
  const firstMarked = useRef<HTMLLIElement | null>(null);
  useEffect(() => {
    firstMarked.current?.scrollIntoView?.({ block: 'center' });
  }, [doc]);
  const firstKey = rows.find(([key]) => marked.has(key))?.[0];
  return (
    <div className="p-4 text-[12.5px]">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5">
        <span className="inline-flex items-center gap-1.5">
          <span className="text-[11px] text-faint">Dataset</span>
          <span className="font-mono text-[11.5px] text-text-2">{doc.dataset ?? 'unknown'}</span>
        </span>
        <span className="inline-flex items-center gap-1.5">
          <span className="text-[11px] text-faint">Timestamp</span>
          <span className="font-mono text-[11.5px] text-text-2">{doc.timestamp ?? 'unknown'}</span>
        </span>
        <span className="ml-auto">
          <CopyJson source={doc.source} />
        </span>
      </div>
      {rows.length === 0 ? (
        <div className="mt-3 text-dim">This document has no fields.</div>
      ) : (
        <ul data-testid="document-source" className="mt-3 divide-y divide-border-faint">
          {rows.map(([key, value]) => {
            const hit = marked.has(key);
            return (
            <li
              key={key}
              ref={key === firstKey ? firstMarked : undefined}
              data-cited={hit ? 'true' : undefined}
              className={`grid grid-cols-[minmax(0,34%)_minmax(0,1fr)] gap-3 py-1.5 ${hit ? 'bg-accent/[.08]' : ''}`}
            >
              <span
                data-testid="document-key"
                className="break-all font-mono text-[11.5px] text-faint"
              >
                {key}
              </span>
              <span className="whitespace-pre-wrap break-all font-mono text-[11.5px] text-text-2">
                {value}
              </span>
            </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}

/** How long a read runs before the drawer says where the time goes. */
export const SLOW_READ_MS = 2000;

/** The read in progress. The grid can take 3 to 15 s for one raw event, and a
 *  still line of text read as a stuck drawer (dogfood 2026-10-06, W3). After
 *  two seconds a spinner and the source of the wait appear. */
function SlowRead() {
  const [slow, setSlow] = useState(false);
  useEffect(() => {
    const t = window.setTimeout(() => setSlow(true), SLOW_READ_MS);
    return () => window.clearTimeout(t);
  }, []);
  return slow ? (
    <span data-testid="document-slow" className="flex items-center gap-2">
      <Spinner size={13} /> Fetching the raw event from Security Onion
    </span>
  ) : (
    <LoadingInline size={13}>Reading the document</LoadingInline>
  );
}

/** The drawer for one document id. `documentId` null keeps it closed and reads
 *  nothing, so a chip can mount it and never fetch until it is clicked. */
export function DocumentDrawer({
  documentId,
  onClose,
  cited,
}: {
  documentId: string | null;
  onClose: () => void;
  /** The field a report cites. The drawer shows it first and marks its row. */
  cited?: CitedField;
}) {
  // An empty id reads nothing. GET /events/ is a route that answers 404 for a
  // reason that has nothing to do with this document.
  const blank = documentId !== null && documentId.trim() === '';
  const doc = useAsync(
    () => (documentId && documentId.trim() ? getEvent(documentId) : Promise.resolve(null)),
    [documentId],
  );
  const data = doc.data;
  // A 404 on this route is an answer and not a fault. The grid ages documents
  // out, and an id that has aged out must read as a document that is gone.
  const gone =
    doc.error instanceof ApiError &&
    (doc.error.reason === 'event_not_found' || doc.error.status === 404);
  return (
    <Drawer
      open={documentId !== null}
      onClose={onClose}
      header={
        <span className="min-w-0 flex-1">
          <span className="block text-[13.5px] font-semibold">Document</span>
          <span data-testid="document-id" className="block break-all font-mono text-[11px] text-faint">
            {documentId ?? ''}
          </span>
        </span>
      }
    >
      {/* The cited field shows while the document loads, and when the grid
          no longer holds the document: the value is what the run read. */}
      {cited && (
        <div className="px-4 pt-1 text-[12.5px]">
          <CitedBlock cited={cited} />
        </div>
      )}
      {!data ? (
        <div className="p-4 text-[12.5px] text-dim">
          {blank ? NO_ID : doc.error ? (gone ? NOT_FOUND : READ_FAILED) : <SlowRead key={documentId} />}
        </div>
      ) : (
        <Body doc={data} cited={cited} />
      )}
    </Drawer>
  );
}

/** One evidence id, as a control that opens the document. Every surface that
 *  cites a document id mounts this, so one id behaves the same everywhere. */
export function DocumentChip({ id, className }: { id: string; className?: string }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button
        type="button"
        title={DOCUMENT_TITLE}
        onClick={() => setOpen(true)}
        className={
          className ??
          'rounded-chip border border-border-strong bg-surface-2 px-1.5 py-px font-mono text-accent hover:bg-surface-3'
        }
      >
        {id}
      </button>
      {/* Mounted only while it is open. `Drawer` registers with the modal stack
          before it renders, so a closed drawer left mounted would put every
          screen that cites a document inside the shell context. */}
      {open && <DocumentDrawer documentId={id} onClose={() => setOpen(false)} />}
    </>
  );
}
