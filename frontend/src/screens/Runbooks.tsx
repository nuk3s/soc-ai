import { BookOpen, Eye, FileUp, History, Pencil, PackagePlus, Plus } from 'lucide-react';
import { useEffect, useId, useMemo, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  type PromotableRule,
  type Runbook,
  type RunbookInput,
  approveRunbook,
  createRunbook,
  deleteRunbook,
  getPromotableRules,
  getRunbooks,
  installStarterPack,
  promoteRunbook,
  updateRunbook,
} from '../lib/api';
import { Markdown } from '../components/Markdown';
import { mdToPlainExcerpt } from '../lib/mdExcerpt';
import { ErrorState, LoadingState, Spinner } from '../components/States';
import { absoluteTime, ago } from '../lib/timeRange';
import { useAsync } from '../lib/useAsync';
import { dominantVerdictLabel, dominantVerdictTitle, formatVerdictMix } from '../lib/verdictMix';

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

/** Amber DRAFT chip — a machine-authored promotion draft awaiting approval.
 * The agent never retrieves a draft, so the badge is the "not live yet" cue. */
function DraftChip() {
  return (
    <span
      title="The draft comes from investigation history. The model does not cite this runbook until you approve it."
      className="rounded px-1.5 py-0.5 text-[10px] font-bold"
      style={{ background: '#f5a62322', color: '#f5a623' }}
    >
      DRAFT
    </span>
  );
}

/** Embed-status chip — rendered only when the semantic tier is on (non-null). */
function EmbedChip({ rb }: { rb: Runbook }) {
  if (rb.embedded === null || rb.embedded === undefined) return null; // tier off → not applicable
  const [label, color, title] =
    rb.embedded === false
      ? [
          'not embedded',
          '#f5a623',
          'This runbook has no embedding vector. The gateway was down during the save. Run “Re-embed runbooks” in Settings → Retrieval.',
        ]
      : rb.stale
        ? [
            'stale embedding',
            '#f5a623',
            'The embedding model is not the configured model. Run “Re-embed runbooks” in Settings → Retrieval.',
          ]
        : ['embedded', '#12b76a', 'The semantic-search vector is current.'];
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

// A Suricata SID or a Sigma UUID. Anything else is a rule name.
const RULE_ID_RE = /^(?:\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i;

/** The Alerts screen, filtered to the alerts of one linked rule over 30 days
 *  (dogfood 2026-10-19, R5-D16). The chip looked like a link and did nothing.
 *  An empty list there says that the rule matched no alert in the window. The
 *  filter is an exact match on the rule name or the rule id. */
function ruleAlertsHref(rule: string): string {
  const field = RULE_ID_RE.test(rule.trim()) ? 'rule.uuid' : 'rule.name';
  const clause = `${field}:"${rule.trim().replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
  return `/alerts?range=30d&hide_acked=false&q=${encodeURIComponent(clause)}`;
}

/**
 * List-row preview text. Most runbooks open with a `# Title` heading that
 * matches the row's own title, so the plain-text excerpt would just repeat the
 * title verbatim on the line right beneath it. Drop that leading duplicate so
 * the preview shows the actual body.
 */
function previewExcerpt(content: string, title: string): string {
  const excerpt = mdToPlainExcerpt(content);
  const t = title.trim();
  if (t && excerpt.toLowerCase().startsWith(t.toLowerCase())) {
    return excerpt.slice(t.length).replace(/^[\s:·–—-]+/, '');
  }
  return excerpt;
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
  // Arms an inline two-step confirm for a row's Delete (matches every other
  // destructive action in the app) — a runbook has no undo / soft-delete.
  const [pendingDelete, setPendingDelete] = useState<number | null>(null);
  // One-line outcome summaries for the two bulk actions (import / pack).
  const [bulkSummary, setBulkSummary] = useState('');
  // The outcome of the last save while the editor stays open (R5-I11).
  const [savedNote, setSavedNote] = useState('');
  // Each label names its control (R5-D23).
  const fieldId = useId();
  const titleId = `${fieldId}-title`;
  const contentId = `${fieldId}-content`;
  const contentLabelId = `${fieldId}-content-label`;
  const tagsId = `${fieldId}-tags`;
  const rulesId = `${fieldId}-rules`;
  const fileInputRef = useRef<HTMLInputElement>(null);
  // ── Draft-from-history (promotion) panel state ────────────────────────────
  // promotable: null = loading (panel open, fetch in flight); [] = none left.
  const [promoOpen, setPromoOpen] = useState(false);
  const [promotable, setPromotable] = useState<PromotableRule[] | null>(null);
  const [promoError, setPromoError] = useState('');
  // The rule whose distillation is in flight — the promote call is synchronous
  // on the server (one model call, seconds to ~a minute), so a per-rule
  // progress state keeps the rest of the panel honest and clickable-looking.
  const [draftingRule, setDraftingRule] = useState<string | null>(null);
  // Whether the runbook open in the editor is an unapproved draft — drives the
  // DRAFT banner + Approve button. Tracked as state (not derived from the list)
  // so a just-promoted draft shows the banner before the list refetch lands.
  const [editingDraft, setEditingDraft] = useState(false);

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

  // Escape cancels an armed delete wherever the focus is (R5-D24).
  useEffect(() => {
    if (pendingDelete === null) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setPendingDelete(null);
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [pendingDelete]);

  const openNew = () => {
    setActionError('');
    setSavedNote('');
    setDraft(EMPTY_DRAFT);
    setPreview(false);
    setEditingDraft(false);
    setEditing('new');
  };
  const openEdit = (rb: Runbook) => {
    setActionError('');
    setSavedNote('');
    setDraft(toDraft(rb));
    // An existing runbook opens RENDERED (it's markdown — reading comes before
    // editing); the Write toggle is one click away. A new runbook starts in
    // write mode since there is nothing to render yet.
    setPreview(true);
    setEditingDraft(rb.draft);
    setEditing(rb.id);
  };
  const cancel = () => {
    setEditing(null);
    setDraft(EMPTY_DRAFT);
    setEditingDraft(false);
    setActionError('');
    setSavedNote('');
  };

  const save = async () => {
    if (!draft.title.trim()) return;
    setBusy(true);
    setActionError('');
    try {
      if (editing === 'new') {
        // The new runbook stays open, so the author can keep writing it
        // (R5-I11). The editor now edits the stored runbook.
        const rb = await createRunbook(toInput(draft));
        setEditing(rb.id);
        setDraft(toDraft(rb));
        setEditingDraft(rb.draft);
        setSavedNote('soc-ai created the runbook.');
      } else if (typeof editing === 'number') {
        await updateRunbook(editing, toInput(draft));
        cancel();
      }
      setNonce((n) => n + 1);
    } catch (e) {
      setActionError(e instanceof Error ? e.message : 'The save failed.');
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
      setActionError(e instanceof Error ? e.message : 'The delete failed.');
    } finally {
      setBusy(false);
      setPendingDelete(null);
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
      setActionError(e instanceof Error ? e.message : 'The starter pack install failed.');
    } finally {
      setBusy(false);
    }
  };

  // ── Draft from history (promotion) ──────────────────────────────────────────

  const togglePromo = async () => {
    setPromoError('');
    if (promoOpen) {
      setPromoOpen(false);
      return;
    }
    setPromoOpen(true);
    setPromotable(null); // loading state
    try {
      setPromotable(await getPromotableRules());
    } catch (e) {
      setPromotable([]);
      setPromoError(e instanceof Error ? e.message : 'The list of promotable rules did not load.');
    }
  };

  // One synchronous model call per click — the button shows its own spinner
  // for the duration; success lands the draft OPEN in the editor with the
  // DRAFT banner, and the rule leaves the list (it's now linked by a runbook).
  const draftFromHistory = async (ruleName: string) => {
    setDraftingRule(ruleName);
    setPromoError('');
    try {
      const rb = await promoteRunbook(ruleName);
      setPromotable((rows) => (rows ?? []).filter((r) => r.rule_name !== ruleName));
      setNonce((n) => n + 1);
      openEdit(rb);
    } catch (e) {
      setPromoError(e instanceof Error ? e.message : `The draft failed for ${ruleName}.`);
    } finally {
      setDraftingRule(null);
    }
  };

  // Approve = publish: saves any pending edits FIRST (approval must publish
  // what's on screen, not a stale draft body), then flips the flag — from that
  // moment the agent can retrieve it (and it embeds when the RAG tier is on).
  const approve = async () => {
    if (typeof editing !== 'number' || !draft.title.trim()) return;
    setBusy(true);
    setActionError('');
    try {
      await updateRunbook(editing, toInput(draft));
      await approveRunbook(editing);
      setEditingDraft(false);
      setNonce((n) => n + 1);
    } catch (e) {
      setActionError(e instanceof Error ? e.message : 'The approval failed.');
    } finally {
      setBusy(false);
    }
  };

  // On lg+ the form is a flex column filling the editor pane: the content
  // field is the flex-1 middle, so the textarea/preview grow with the
  // viewport instead of a fixed 12-row box. Below lg it keeps a generous
  // min-height (55vh) and stays resizable.
  const form = (
    <div className="flex min-h-0 flex-col rounded-card border border-border bg-surface-1 p-3.5 lg:flex-1">
      {/* DRAFT banner: visible whenever an unapproved promotion draft is open.
          Approve is the ONLY way a draft becomes agent-retrievable. */}
      {editingDraft && typeof editing === 'number' && (
        <div
          className="mb-3 flex flex-none flex-wrap items-center gap-2.5 rounded-control border px-3 py-2"
          style={{ borderColor: 'rgba(245,166,35,.45)', background: 'rgba(245,166,35,.08)' }}
        >
          <DraftChip />
          <span className="min-w-[200px] flex-1 text-[12px] leading-[1.45] text-dim">
            The draft comes from this rule's investigation history. Review the draft and edit
            it. The model does not cite the draft until you approve it.
          </span>
          <button
            onClick={() => void approve()}
            disabled={busy || !draft.title.trim()}
            className="rounded-[7px] border px-[13px] py-1.5 text-[12px] font-semibold disabled:cursor-not-allowed disabled:opacity-50"
            style={{ borderColor: '#f5a623', color: '#f5a623' }}
          >
            {busy ? 'Working' : 'Approve'}
          </button>
        </div>
      )}
      <div className="mb-3">
        <label htmlFor={titleId} className={labelCls}>
          Title
        </label>
        <input
          id={titleId}
          value={draft.title}
          onChange={(e) => setDraft({ ...draft, title: e.target.value })}
          placeholder="Example: Triage an ET SCAN Nmap alert"
          className={inputCls}
        />
      </div>
      <div className="mb-3 flex min-h-0 flex-1 flex-col">
        <div className="mb-1 flex flex-none items-center justify-between">
          {/* In the preview the label names the rendered region. */}
          <label
            id={contentLabelId}
            htmlFor={preview ? undefined : contentId}
            className="block text-[11px] font-semibold uppercase tracking-[.06em] text-faint"
          >
            Markdown content
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
          <div
            role="region"
            aria-labelledby={contentLabelId}
            className="min-h-[55vh] flex-1 overflow-y-auto rounded-control border border-border-input bg-bg px-3 py-2 text-[12.5px] leading-[1.55] text-text lg:min-h-[240px]"
          >
            {draft.content.trim() ? (
              <Markdown>{draft.content}</Markdown>
            ) : (
              <span className="italic text-faint">The content is empty. Select Write to add markdown.</span>
            )}
          </div>
        ) : (
          <textarea
            id={contentId}
            value={draft.content}
            onChange={(e) => setDraft({ ...draft, content: e.target.value })}
            placeholder="The procedure the model cites. Describe what is normal on this network. Give the confirm steps and the dismiss steps. Name the known-benign hosts and the pivot queries."
            rows={12}
            className={`${inputCls} min-h-[55vh] flex-1 resize-y font-mono leading-[1.55] lg:min-h-[240px] lg:resize-none`}
          />
        )}
      </div>
      <div className="mb-3 grid flex-none grid-cols-2 gap-3">
        <div>
          <label htmlFor={tagsId} className={labelCls}>
            Tags
          </label>
          <input
            id={tagsId}
            value={draft.tags}
            onChange={(e) => setDraft({ ...draft, tags: e.target.value })}
            placeholder="Separate tags with a comma. Example: scan, recon"
            className={inputCls}
          />
        </div>
        <div>
          <label htmlFor={rulesId} className={labelCls}>
            Linked rules
          </label>
          <input
            id={rulesId}
            value={draft.linked_rules}
            onChange={(e) => setDraft({ ...draft, linked_rules: e.target.value })}
            placeholder="Rule names or UUIDs. A linked rule ranks the runbook first."
            className={inputCls}
          />
        </div>
      </div>
      {actionError && <div className="mb-2 text-[12px] text-danger">{actionError}</div>}
      {savedNote && !actionError && (
        <div role="status" className="mb-2 text-[12px] text-success">
          {savedNote}
        </div>
      )}
      <div className="flex items-center gap-2">
        <button
          onClick={() => void save()}
          disabled={busy || !draft.title.trim()}
          className="rounded-[7px] border border-accent px-[13px] py-1.5 text-[12px] font-semibold text-accent disabled:cursor-not-allowed disabled:opacity-50"
        >
          {busy ? 'Saving' : editing === 'new' ? 'Create runbook' : 'Save changes'}
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

  // Two-pane workspace on lg+: list (search + rows) on the left ~1/3, editor
  // filling the rest. DOM order puts the editor pane FIRST so it stacks above
  // the list on narrow screens (the old inline-form behavior);
  // lg:flex-row-reverse flips it to the right visually. The page goes
  // full-width (the Alerts idiom — the shell imposes no max-width) and on lg+
  // pins to the viewport height with each pane scrolling internally, so the
  // editor always gets the whole window.
  return (
    <div className="flex flex-col px-[22px] pb-[60px] pt-5 lg:h-full lg:pb-4">
      <div className="flex flex-none items-center gap-2.5">
        <BookOpen size={19} className="text-accent" />
        <div className="text-[20px] font-semibold tracking-[-.015em]">Runbooks</div>
      </div>
      <div data-tour="runbooks-header" className="mb-4 mt-0.5 max-w-[880px] flex-none text-[13px] leading-[1.55] text-dim">
        A runbook holds your team's own triage guidance. During an investigation, the model
        searches the runbooks and cites the best match. The verdict then cites <strong>your</strong> procedure. A runbook that names a
        detection rule under <em>Linked rules</em> ranks first if that rule fires. Every runbook
        stays local. soc-ai never writes a runbook to Security Onion.
      </div>

      {/* toolbar: bulk actions + new (search lives in the list pane) */}
      <div data-tour="runbooks-toolbar" className="mb-3 flex flex-none flex-wrap items-center gap-2">
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
          title="Import one or more markdown files. Each file can carry optional front-matter with title, tags and rules."
          className={toolbarBtnCls}
        >
          <FileUp size={13} />
          Import files
        </button>
        <button
          onClick={() => void loadPack()}
          disabled={busy}
          title="Add the shipped starter pack of 10 generic SOC runbooks. The pack covers beaconing, scans, brute force, DNS, phishing, lateral movement, data exfiltration, cryptomining, TLS and tuning. The pack skips any title you already have."
          className={toolbarBtnCls}
        >
          {busy ? <Spinner size={12} /> : <PackagePlus size={13} />}
          Load starter pack
        </button>
        <button
          data-tour="runbooks-draft"
          onClick={() => void togglePromo()}
          disabled={busy}
          title="Draft a runbook from the investigations this deployment already ran. The model writes a draft for this network. You review and approve it."
          className={toolbarBtnCls}
        >
          <History size={13} />
          Draft from history
        </button>
        {editing === null && (
          <button onClick={openNew} disabled={busy} className={toolbarBtnCls}>
            <Plus size={13} />
            New runbook
          </button>
        )}
      </div>

      {/* Draft-from-history panel: the promotable rules with per-rule Draft it.
          Kept above the workspace so drafting flows straight into the editor. */}
      {promoOpen && (
        <div className="mb-3 flex-none rounded-card border border-border bg-surface-1 px-3.5 py-3">
          <div className="mb-1.5 text-[12px] font-semibold text-text">
            Draft a runbook from investigation history
          </div>
          <div className="mb-2 max-w-[720px] text-[11.5px] leading-[1.5] text-faint">
            The list holds each rule with 3 or more completed investigations and no runbook. The
            model summarizes the verdicts, the rationales and the analyst chat into a draft for
            this network. The model uses no draft until you approve it.
          </div>
          {promoError && <div className="mb-2 text-[12px] text-danger">{promoError}</div>}
          {promotable === null && <LoadingState />}
          {promotable !== null && promotable.length === 0 && !promoError && (
            <div className="py-1 text-[12.5px] text-faint">
              No rule is ready to draft. Either every rule with enough history already has a
              runbook, or no rule has 3 or more completed investigations. A draft counts as a
              runbook.
            </div>
          )}
          {(promotable ?? []).map((r) => (
            <div
              key={r.rule_name}
              className="flex flex-wrap items-center gap-2.5 border-t border-border-faint py-2 first:border-t-0"
            >
              <span className="min-w-0 flex-1 break-words text-[12.5px] font-medium" title={r.rule_name}>
                {r.rule_name}
              </span>
              <span className="text-[11.5px] text-faint">
                {r.investigations} investigation{r.investigations === 1 ? '' : 's'} ·{' '}
                {formatVerdictMix(r)}
              </span>
              <span
                className="rounded border border-border-strong bg-surface-3 px-1.5 py-0.5 text-[10.5px] text-dim"
                title={dominantVerdictTitle(r.dominant_verdict)}
              >
                {dominantVerdictLabel(r.dominant_verdict)}
              </span>
              <button
                onClick={() => void draftFromHistory(r.rule_name)}
                disabled={busy || draftingRule !== null || editing !== null}
                title={
                  editing !== null
                    ? 'Close the open editor first. The new draft opens there.'
                    : 'Make one call to the model. It summarizes the history of this rule into a draft. The call can take up to a minute.'
                }
                className={toolbarBtnCls}
              >
                {draftingRule === r.rule_name ? <Spinner size={12} /> : <History size={13} />}
                {draftingRule === r.rule_name ? 'Drafting' : 'Draft it'}
              </button>
            </div>
          ))}
        </div>
      )}

      {bulkSummary && (
        <div className="mb-3 flex-none rounded-control border border-border bg-surface-1 px-3 py-2 text-[12px] text-text">
          {bulkSummary}
        </div>
      )}
      {actionError && editing === null && (
        <div className="mb-3 flex-none text-[12px] text-danger">{actionError}</div>
      )}

      <div className="flex min-h-0 flex-col gap-4 lg:flex-1 lg:flex-row-reverse">
        {/* editor pane — the form when open, else a hint card (lg+ only; on
            narrow screens the pane vanishes entirely when nothing is open). */}
        <div
          data-tour="runbooks-editor"
          className={`${editing === null ? 'hidden lg:flex' : 'flex'} min-w-0 flex-1 flex-col lg:min-h-0`}
        >
          {editing !== null ? (
            form
          ) : (
            <div className="flex flex-1 flex-col items-center justify-center gap-2 rounded-card border border-dashed border-border bg-surface-1/50 px-6 py-10 text-center">
              <BookOpen size={22} className="text-faint" />
              <div className="text-[13px] font-medium text-dim">No runbook open</div>
              <div className="max-w-[380px] text-[12px] text-faint">
                Select a runbook from the list to edit it here. Select New runbook to start one.
              </div>
              <button onClick={openNew} disabled={busy} className={`${toolbarBtnCls} mt-1`}>
                <Plus size={13} />
                New runbook
              </button>
            </div>
          )}
        </div>

        {/* list pane: search + rows; scrolls internally on lg+ */}
        <div className="flex min-h-0 flex-none flex-col lg:w-1/3 lg:min-w-[300px] lg:max-w-[440px]">
          <input
            data-tour="runbooks-search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={`Search ${runbooks.length} runbook${runbooks.length === 1 ? '' : 's'}`}
            className="mb-2 w-full flex-none rounded-control border border-border-input bg-bg px-3 py-1.5 text-[12.5px] text-text outline-none focus:border-accent"
          />
          <div
            data-tour="runbooks-list"
            className="overflow-hidden rounded-card border border-border bg-surface-1 lg:flex-1 lg:overflow-y-auto"
          >
            {loading && <LoadingState />}
            {error && (
              <div className="p-3">
                <ErrorState error={error} />
              </div>
            )}
            {!loading && !error && runbooks.length === 0 && editing !== 'new' && (
              <div className="px-3.5 py-5 text-[12.5px] text-faint">
                No runbooks yet. Write one, import your .md procedures, or load the starter pack.
                The model then has a runbook to cite.
              </div>
            )}
            {!loading && !error && runbooks.length > 0 && visible.length === 0 && (
              <div className="px-3.5 py-4 text-[12.5px] text-faint">
                No runbooks match “{query}”.
              </div>
            )}
            {!loading &&
              !error &&
              visible.map((rb) => {
                const preview = rb.content ? previewExcerpt(rb.content, rb.title) : '';
                return (
                <div
                  key={rb.id}
                  className={`border-b border-border-faint px-3.5 py-3 last:border-b-0 ${editing === rb.id ? 'bg-[#11161e]' : ''}`}
                >
                  <div className="flex items-start gap-3">
                    <div className="min-w-0 flex-1">
                      {/* The whole title/body area opens the runbook — the Edit
                          button is no longer the only way in (dogfood). */}
                      <button
                        type="button"
                        onClick={() => openEdit(rb)}
                        disabled={busy || editing !== null}
                        className="w-full min-w-0 text-left disabled:cursor-default"
                      >
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="break-words text-[13px] font-medium" title={rb.title}>
                            {rb.title}
                          </span>
                          {rb.draft && <DraftChip />}
                          <EmbedChip rb={rb} />
                          <span
                            className="text-[10.5px] text-faint"
                            title={absoluteTime(rb.updated_at)}
                            data-testid={`runbook-updated-${rb.id}`}
                          >
                            updated {ago(rb.updated_at)}
                          </span>
                        </div>
                        {preview && (
                          // The body of a runbook runs to pages, so the row
                          // shows its first three lines and the hover holds the
                          // whole text. The box stops at the line edge and draws
                          // no ellipsis (owner, 2026-10-07). The row opens the
                          // runbook.
                          <div
                            data-testid={`runbook-preview-${rb.id}`}
                            title={preview}
                            className="mt-0.5 max-h-[4.2em] overflow-hidden break-words text-[11.5px] leading-[1.4] text-faint"
                          >
                            {preview}
                          </div>
                        )}
                      </button>
                      {/* The chips sit outside the row button: a link inside a
                          button is invalid markup, and its click opened the
                          editor. A linked rule opens its alerts (R5-D16). */}
                      {(rb.linked_rules.length > 0 || rb.tags.length > 0) && (
                        <div className="mt-1.5 flex flex-wrap gap-1.5">
                          {rb.linked_rules.map((r) => (
                            <Link
                              key={`r-${r}`}
                              to={ruleAlertsHref(r)}
                              title="Show the alerts of this rule in the last 30 days. An empty list means that the rule matched no alert."
                              aria-label={`Alerts of the linked rule ${r}`}
                              className="rounded border border-accent/40 px-1.5 py-0.5 text-[10.5px] text-accent underline-offset-2 hover:border-accent hover:underline"
                            >
                              {r}
                            </Link>
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
                      )}
                    </div>
                    <div className="flex flex-none items-center gap-1.5">
                      <button
                        onClick={() => openEdit(rb)}
                        disabled={busy || editing !== null}
                        className="rounded-[7px] border border-border-strong bg-surface-3 px-[11px] py-[5px] text-[11.5px] font-semibold text-text hover:border-accent disabled:cursor-not-allowed disabled:opacity-40"
                      >
                        Edit
                      </button>
                      {pendingDelete === rb.id ? (
                        <>
                          <button
                            onClick={() => void remove(rb.id)}
                            disabled={busy}
                            className="rounded-[7px] border border-danger px-[11px] py-[5px] text-[11.5px] font-semibold text-danger hover:bg-[rgba(240,68,56,.12)] disabled:cursor-not-allowed disabled:opacity-40"
                          >
                            Confirm delete
                          </button>
                          {/* The safe choice holds the focus. */}
                          <button
                            autoFocus
                            onClick={() => setPendingDelete(null)}
                            disabled={busy}
                            className="rounded-[7px] border border-border-strong bg-surface-3 px-[11px] py-[5px] text-[11.5px] font-semibold text-dim hover:text-text disabled:cursor-not-allowed disabled:opacity-40"
                          >
                            Cancel
                          </button>
                        </>
                      ) : (
                        <button
                          onClick={() => setPendingDelete(rb.id)}
                          disabled={busy || editing !== null}
                          className="rounded-[7px] border px-[11px] py-[5px] text-[11.5px] font-semibold text-danger hover:bg-[rgba(240,68,56,.12)] disabled:cursor-not-allowed disabled:opacity-40"
                          style={{ borderColor: 'rgba(240,68,56,.3)' }}
                        >
                          Delete
                        </button>
                      )}
                    </div>
                  </div>
                  {/* What a delete does, beside the armed confirm (R5-D24). */}
                  {pendingDelete === rb.id && (
                    <div
                      data-testid={`runbook-delete-confirm-${rb.id}`}
                      role="alert"
                      className="mt-2 text-[11.5px] leading-[1.45] text-danger"
                    >
                      Select Confirm delete to remove the runbook “{rb.title}”. The model then stops
                      citing it. You cannot undo this.
                    </div>
                  )}
                </div>
                );
              })}
          </div>
        </div>
      </div>
    </div>
  );
}
