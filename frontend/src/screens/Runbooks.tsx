import { BookOpen, Eye, FileUp, Pencil, PackagePlus, Plus } from 'lucide-react';
import { useMemo, useRef, useState } from 'react';
import {
  type Runbook,
  type RunbookInput,
  createRunbook,
  deleteRunbook,
  getRunbooks,
  installStarterPack,
  updateRunbook,
} from '../lib/api';
import { Markdown } from '../components/Markdown';
import { ErrorState, LoadingState, Spinner } from '../components/States';
import { useAsync } from '../lib/useAsync';

// ---------------------------------------------------------------------------
// Runbooks — the first-class authoring space for the org's own triage
// guidance. The investigation agent's `lookup_runbook` tool searches these
// (rule-link > tag > keyword, plus the opt-in semantic tier), so everything
// written here directly shapes verdicts. The Config page keeps only a compact
// summary linking back to this screen.
// ---------------------------------------------------------------------------

/** A comma/newline-separated string ↔ a clean string[] (the store normalizes too). */
function parseList(s: string): string[] {
  return s
    .split(/[,\n]/)
    .map((t) => t.trim())
    .filter(Boolean);
}

// ── Lenient .md front-matter import ─────────────────────────────────────────
// Mirrors the server-side parser (soc_ai/store/runbook_pack.py) so a file
// authored for the shipped starter pack imports identically through the
// browser: optional ----fenced YAML with title / tags / rules (or
// linked_rules); malformed lines are ignored (metadata is a bonus, never a
// gate); title precedence front-matter → first # heading → filename.

interface ParsedImport {
  title: string;
  content: string;
  tags: string[];
  linked_rules: string[];
}

/** "[a, b]" / "a, b" / "a" → clean string[] with quotes stripped. */
function parseYamlishList(raw: string): string[] {
  const inner = raw.trim().replace(/^\[/, '').replace(/\]$/, '');
  return inner
    .split(',')
    .map((t) => t.trim().replace(/^["']|["']$/g, '').trim())
    .filter(Boolean);
}

/**
 * Hand-rolled lenient front-matter reader (no YAML dependency in the bundle).
 * Understands the three shapes the pack files and typical wiki exports use:
 * `key: value`, `key: [a, b]`, and a `key:` line followed by `- item` lines.
 * Anything else is skipped silently — the body still imports.
 */
function parseRunbookMarkdown(text: string, fallbackTitle: string): ParsedImport {
  let body = text;
  const meta: { title?: string; tags?: string[]; rules?: string[] } = {};

  const fence = text.match(/^---[ \t]*\r?\n([\s\S]*?)\r?\n---[ \t]*\r?\n?/);
  if (fence) {
    body = text.slice(fence[0].length);
    let pendingList: 'tags' | 'rules' | null = null;
    for (const rawLine of fence[1].split(/\r?\n/)) {
      const dashItem = rawLine.match(/^\s*-\s+(.*)$/);
      if (pendingList && dashItem) {
        const value = dashItem[1].trim().replace(/^["']|["']$/g, '').trim();
        if (value) (meta[pendingList] = meta[pendingList] ?? []).push(value);
        continue;
      }
      pendingList = null;
      const kv = rawLine.match(/^([A-Za-z_][\w-]*)\s*:\s*(.*)$/);
      if (!kv) continue; // malformed line → ignored, never fatal
      const key = kv[1].toLowerCase();
      const value = kv[2].trim();
      if (key === 'title' && value) {
        meta.title = value.replace(/^["']|["']$/g, '').trim();
      } else if (key === 'tags' || key === 'rules' || key === 'linked_rules') {
        const target = key === 'tags' ? 'tags' : 'rules';
        if (value) meta[target] = parseYamlishList(value);
        else pendingList = target; // dash-list items follow on the next lines
      }
    }
  }

  let title = meta.title ?? '';
  if (!title) {
    const heading = body.match(/^#\s+(.+?)\s*$/m);
    title = heading ? heading[1].trim() : '';
  }
  if (!title) title = fallbackTitle.trim() || 'Untitled runbook';

  return {
    title: title.slice(0, 512), // same cap as the API's RunbookIn
    content: body.trim(),
    tags: meta.tags ?? [],
    linked_rules: meta.rules ?? [],
  };
}

// ── Editor draft state (same shape as the old Config panel) ─────────────────

interface DraftState {
  title: string;
  content: string;
  tags: string;
  linked_rules: string;
}

const EMPTY_DRAFT: DraftState = { title: '', content: '', tags: '', linked_rules: '' };

function toDraft(rb: Runbook): DraftState {
  return {
    title: rb.title,
    content: rb.content,
    tags: rb.tags.join(', '),
    linked_rules: rb.linked_rules.join(', '),
  };
}

function toInput(d: DraftState): RunbookInput {
  return {
    title: d.title.trim(),
    content: d.content,
    tags: parseList(d.tags),
    linked_rules: parseList(d.linked_rules),
  };
}

const inputCls =
  'w-full rounded-control border border-border-input bg-bg px-3 py-1.5 text-[12.5px] text-text outline-none focus:border-accent';
const labelCls = 'mb-1 block text-[11px] font-semibold uppercase tracking-[.06em] text-faint';
const toolbarBtnCls =
  'inline-flex items-center gap-1.5 rounded-[7px] border border-border-strong bg-surface-3 px-[11px] py-[5px] text-[11.5px] font-semibold text-text hover:border-accent disabled:cursor-not-allowed disabled:opacity-40';

/** Embed-status chip — rendered only when the semantic tier is on (non-null). */
function EmbedChip({ rb }: { rb: Runbook }) {
  if (rb.embedded === null || rb.embedded === undefined) return null; // tier off → not applicable
  const [label, color, title] =
    rb.embedded === false
      ? [
          'not embedded',
          '#f5a623',
          'No embedding vector yet (the gateway was down during the save) — run “Re-embed runbooks” in Config → Retrieval.',
        ]
      : rb.stale
        ? [
            'stale embedding',
            '#f5a623',
            'Embedded by a different model than currently configured — run “Re-embed runbooks” in Config → Retrieval.',
          ]
        : ['embedded', '#12b76a', 'Semantic-search vector is current.'];
  return (
    <span
      title={title}
      className="rounded px-1.5 py-0.5 text-[10px] font-semibold"
      style={{ background: `${color}22`, color }}
    >
      {label}
    </span>
  );
}

export function Runbooks() {
  const [nonce, setNonce] = useState(0);
  const { data, loading, error } = useAsync(getRunbooks, [nonce]);
  const [query, setQuery] = useState('');
  // null = form closed; 'new' = add form; a number = editing that runbook.
  const [editing, setEditing] = useState<'new' | number | null>(null);
  const [draft, setDraft] = useState<DraftState>(EMPTY_DRAFT);
  const [preview, setPreview] = useState(false);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState('');
  // One-line outcome summaries for the two bulk actions (import / pack).
  const [bulkSummary, setBulkSummary] = useState('');
  const fileInputRef = useRef<HTMLInputElement>(null);

  const runbooks: Runbook[] = useMemo(() => data ?? [], [data]);

  // Client-side search — the corpus is a few hundred rows at most, so
  // filtering in the browser beats a server round-trip per keystroke. Every
  // whitespace-separated term must match somewhere (title/tags/rules/body).
  const visible = useMemo(() => {
    const terms = query.toLowerCase().split(/\s+/).filter(Boolean);
    if (!terms.length) return runbooks;
    return runbooks.filter((rb) => {
      const hay =
        `${rb.title}\n${rb.tags.join(' ')}\n${rb.linked_rules.join(' ')}\n${rb.content}`.toLowerCase();
      return terms.every((t) => hay.includes(t));
    });
  }, [runbooks, query]);

  const openNew = () => {
    setActionError('');
    setDraft(EMPTY_DRAFT);
    setPreview(false);
    setEditing('new');
  };
  const openEdit = (rb: Runbook) => {
    setActionError('');
    setDraft(toDraft(rb));
    setPreview(false);
    setEditing(rb.id);
  };
  const cancel = () => {
    setEditing(null);
    setDraft(EMPTY_DRAFT);
    setActionError('');
  };

  const save = async () => {
    if (!draft.title.trim()) return;
    setBusy(true);
    setActionError('');
    try {
      if (editing === 'new') {
        await createRunbook(toInput(draft));
      } else if (typeof editing === 'number') {
        await updateRunbook(editing, toInput(draft));
      }
      cancel();
      setNonce((n) => n + 1);
    } catch (e) {
      setActionError(e instanceof Error ? e.message : 'Save failed');
    } finally {
      setBusy(false);
    }
  };

  const remove = async (id: number) => {
    setBusy(true);
    setActionError('');
    try {
      await deleteRunbook(id);
      if (editing === id) cancel();
      setNonce((n) => n + 1);
    } catch (e) {
      setActionError(e instanceof Error ? e.message : 'Delete failed');
    } finally {
      setBusy(false);
    }
  };

  // Import: read each picked .md locally (File API — no new dependency),
  // parse the lenient front-matter, and POST through the SAME create endpoint
  // the editor uses — so validation and the fail-soft write-time embed apply
  // identically. Per-file failures don't abort the batch; the summary is honest.
  const importFiles = async (files: FileList | null) => {
    if (!files || files.length === 0) return;
    setBusy(true);
    setBulkSummary('');
    setActionError('');
    let imported = 0;
    let failed = 0;
    for (const file of Array.from(files)) {
      try {
        const text = await file.text();
        const parsed = parseRunbookMarkdown(text, file.name.replace(/\.(md|markdown|txt)$/i, ''));
        await createRunbook(parsed);
        imported += 1;
      } catch {
        failed += 1;
      }
    }
    setBulkSummary(`Import: ${imported} imported${failed ? `, ${failed} failed` : ''}`);
    setBusy(false);
    setNonce((n) => n + 1);
  };

  const loadPack = async () => {
    setBusy(true);
    setBulkSummary('');
    setActionError('');
    try {
      const r = await installStarterPack();
      setBulkSummary(`Starter pack: ${r.created} added, ${r.skipped} already present`);
      setNonce((n) => n + 1);
    } catch (e) {
      setActionError(e instanceof Error ? e.message : 'Starter pack failed');
    } finally {
      setBusy(false);
    }
  };

  const form = (
    <div className="rounded-card border border-border bg-surface-1 p-3.5">
      <div className="mb-3">
        <label className={labelCls}>Title</label>
        <input
          value={draft.title}
          onChange={(e) => setDraft({ ...draft, title: e.target.value })}
          placeholder="e.g. Triage an ET SCAN Nmap alert"
          className={inputCls}
        />
      </div>
      <div className="mb-3">
        <div className="mb-1 flex items-center justify-between">
          <label className="block text-[11px] font-semibold uppercase tracking-[.06em] text-faint">
            Content (markdown)
          </label>
          <button
            type="button"
            onClick={() => setPreview((p) => !p)}
            className="inline-flex items-center gap-1 text-[11px] font-semibold text-dim hover:text-text"
          >
            {preview ? <Pencil size={11} /> : <Eye size={11} />}
            {preview ? 'Write' : 'Preview'}
          </button>
        </div>
        {preview ? (
          <div className="min-h-[200px] rounded-control border border-border-input bg-bg px-3 py-2 text-[12.5px] leading-[1.55] text-text">
            {draft.content.trim() ? (
              <Markdown>{draft.content}</Markdown>
            ) : (
              <span className="italic text-faint">Nothing to preview yet.</span>
            )}
          </div>
        ) : (
          <textarea
            value={draft.content}
            onChange={(e) => setDraft({ ...draft, content: e.target.value })}
            placeholder="The procedure the agent should cite. What normal looks like on this network, the confirm/dismiss steps, known-benign hosts, pivot queries…"
            rows={12}
            className={`${inputCls} resize-y font-mono leading-[1.55]`}
          />
        )}
      </div>
      <div className="mb-3 grid grid-cols-2 gap-3">
        <div>
          <label className={labelCls}>Tags</label>
          <input
            value={draft.tags}
            onChange={(e) => setDraft({ ...draft, tags: e.target.value })}
            placeholder="comma-separated — e.g. scan, recon"
            className={inputCls}
          />
        </div>
        <div>
          <label className={labelCls}>Linked rules</label>
          <input
            value={draft.linked_rules}
            onChange={(e) => setDraft({ ...draft, linked_rules: e.target.value })}
            placeholder="rule names / UUIDs — strongest match signal"
            className={inputCls}
          />
        </div>
      </div>
      {actionError && <div className="mb-2 text-[12px] text-danger">{actionError}</div>}
      <div className="flex items-center gap-2">
        <button
          onClick={() => void save()}
          disabled={busy || !draft.title.trim()}
          className="rounded-[7px] border border-accent px-[13px] py-1.5 text-[12px] font-semibold text-accent disabled:cursor-not-allowed disabled:opacity-50"
        >
          {busy ? 'Saving…' : editing === 'new' ? 'Create runbook' : 'Save changes'}
        </button>
        <button
          onClick={cancel}
          className="rounded-[7px] border border-border-strong px-[13px] py-1.5 text-[12px] font-semibold text-dim hover:text-text"
        >
          Cancel
        </button>
      </div>
    </div>
  );

  return (
    <div className="mx-auto max-w-permalink px-[22px] pb-[60px] pt-5">
      <div className="flex items-center gap-2.5">
        <BookOpen size={19} className="text-accent" />
        <div className="text-[20px] font-semibold tracking-[-.015em]">Runbooks</div>
      </div>
      <div className="mb-4 mt-0.5 text-[13px] leading-[1.55] text-dim">
        Your team's own triage guidance — the investigation agent searches these (via the{' '}
        <code className="text-[12px] text-text">lookup_runbook</code> tool) and cites the best
        match, so verdicts ground in <strong>your</strong> procedures instead of guessing from thin
        data. A runbook that names a detection rule under <em>Linked rules</em> is preferred
        whenever that rule fires. Purely local — nothing here is ever written to Security Onion.
      </div>

      {/* toolbar: search + bulk actions + new */}
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder={`Search ${runbooks.length} runbook${runbooks.length === 1 ? '' : 's'}…`}
          className="w-[260px] rounded-control border border-border-input bg-bg px-3 py-1.5 text-[12.5px] text-text outline-none focus:border-accent"
        />
        <div className="flex-1" />
        {/* Import: hidden file input driven by the button (browser File API). */}
        <input
          ref={fileInputRef}
          type="file"
          accept=".md,.markdown,.txt,text/markdown,text/plain"
          multiple
          className="hidden"
          onChange={(e) => {
            void importFiles(e.target.files);
            e.target.value = ''; // allow re-picking the same files
          }}
        />
        <button
          onClick={() => fileInputRef.current?.click()}
          disabled={busy}
          title="Import one or more markdown files. Optional front-matter: title, tags, rules."
          className={toolbarBtnCls}
        >
          <FileUp size={13} />
          Import files…
        </button>
        <button
          onClick={() => void loadPack()}
          disabled={busy}
          title="Add the shipped starter pack: 10 generic SOC runbooks (beaconing, scans, brute force, DNS, phishing, lateral movement, exfil, mining, TLS, tuning). Skips any title you already have."
          className={toolbarBtnCls}
        >
          {busy ? <Spinner size={12} /> : <PackagePlus size={13} />}
          Load starter pack
        </button>
        {editing === null && (
          <button onClick={openNew} disabled={busy} className={toolbarBtnCls}>
            <Plus size={13} />
            New runbook
          </button>
        )}
      </div>

      {bulkSummary && (
        <div className="mb-3 rounded-control border border-border bg-surface-1 px-3 py-2 text-[12px] text-text">
          {bulkSummary}
        </div>
      )}
      {actionError && editing === null && (
        <div className="mb-3 text-[12px] text-danger">{actionError}</div>
      )}

      {editing === 'new' && <div className="mb-4">{form}</div>}

      <div className="overflow-hidden rounded-card border border-border bg-surface-1">
        {loading && <LoadingState />}
        {error && (
          <div className="p-3">
            <ErrorState error={error} />
          </div>
        )}
        {!loading && !error && runbooks.length === 0 && editing !== 'new' && (
          <div className="px-3.5 py-5 text-[12.5px] text-faint">
            No runbooks yet. Write one, import your existing .md procedures, or load the starter
            pack to give the agent something to cite.
          </div>
        )}
        {!loading && !error && runbooks.length > 0 && visible.length === 0 && (
          <div className="px-3.5 py-4 text-[12.5px] text-faint">
            No runbooks match “{query}”.
          </div>
        )}
        {!loading &&
          !error &&
          visible.map((rb) => (
            <div key={rb.id} className="border-b border-border-faint px-3.5 py-3 last:border-b-0">
              {editing === rb.id ? (
                form
              ) : (
                <div className="flex items-start gap-3">
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="truncate text-[13px] font-medium" title={rb.title}>
                        {rb.title}
                      </span>
                      <EmbedChip rb={rb} />
                      <span className="text-[10.5px] text-faint">
                        updated {new Date(rb.updated_at).toLocaleString()}
                      </span>
                    </div>
                    {rb.content && (
                      <div className="mt-0.5 line-clamp-2 text-[11.5px] leading-[1.4] text-faint">
                        {rb.content}
                      </div>
                    )}
                    <div className="mt-1.5 flex flex-wrap gap-1.5">
                      {rb.linked_rules.map((r) => (
                        <span
                          key={`r-${r}`}
                          className="rounded border border-accent/40 px-1.5 py-0.5 text-[10.5px] text-accent"
                          title="linked rule"
                        >
                          {r}
                        </span>
                      ))}
                      {rb.tags.map((t) => (
                        <span
                          key={`t-${t}`}
                          className="rounded border border-border-strong bg-surface-3 px-1.5 py-0.5 text-[10.5px] text-dim"
                        >
                          {t}
                        </span>
                      ))}
                    </div>
                  </div>
                  <div className="flex flex-none items-center gap-1.5">
                    <button
                      onClick={() => openEdit(rb)}
                      disabled={busy || editing !== null}
                      className="rounded-[7px] border border-border-strong bg-surface-3 px-[11px] py-[5px] text-[11.5px] font-semibold text-text hover:border-accent disabled:cursor-not-allowed disabled:opacity-40"
                    >
                      Edit
                    </button>
                    <button
                      onClick={() => void remove(rb.id)}
                      disabled={busy || editing !== null}
                      className="rounded-[7px] border px-[11px] py-[5px] text-[11.5px] font-semibold text-danger hover:bg-[rgba(240,68,56,.12)] disabled:cursor-not-allowed disabled:opacity-40"
                      style={{ borderColor: 'rgba(240,68,56,.3)' }}
                    >
                      Delete
                    </button>
                  </div>
                </div>
              )}
            </div>
          ))}
      </div>
    </div>
  );
}
