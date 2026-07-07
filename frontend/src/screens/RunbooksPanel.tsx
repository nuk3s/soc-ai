import { useState } from 'react';
import {
  type Runbook,
  type RunbookInput,
  createRunbook,
  deleteRunbook,
  getRunbooks,
  updateRunbook,
} from '../lib/api';
import { CollapseChevron } from '../components/Panel';
import { ErrorState, LoadingState } from '../components/States';
import { useAsync } from '../lib/useAsync';

/** A comma/newline-separated string ↔ a clean string[] (the store normalizes too). */
function parseList(s: string): string[] {
  return s
    .split(/[,\n]/)
    .map((t) => t.trim())
    .filter(Boolean);
}

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

/**
 * Operator runbooks — the org's own triage guidance the agent can cite.
 *
 * The triage agent's ``lookup_runbook`` tool searches these (rule-link > tag >
 * keyword), so an investigation can ground itself in real operator knowledge
 * instead of hallucinating a false-positive from thin data. Purely local —
 * nothing here is ever written to Security Onion.
 */
export function RunbooksPanel({
  collapsed = false,
  onToggleCollapse,
}: {
  collapsed?: boolean;
  onToggleCollapse?: () => void;
} = {}) {
  const [nonce, setNonce] = useState(0);
  const { data, loading, error } = useAsync(getRunbooks, [nonce]);
  // null = form closed; 'new' = add form; a number = editing that runbook.
  const [editing, setEditing] = useState<'new' | number | null>(null);
  const [draft, setDraft] = useState<DraftState>(EMPTY_DRAFT);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState('');

  const runbooks: Runbook[] = data ?? [];

  const openNew = () => {
    setActionError('');
    setDraft(EMPTY_DRAFT);
    setEditing('new');
  };
  const openEdit = (rb: Runbook) => {
    setActionError('');
    setDraft(toDraft(rb));
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
        <label className={labelCls}>Content</label>
        <textarea
          value={draft.content}
          onChange={(e) => setDraft({ ...draft, content: e.target.value })}
          placeholder="The procedure / notes (markdown ok). What normal looks like on this network, the confirm/dismiss steps, known-benign hosts…"
          rows={7}
          className={`${inputCls} resize-y font-mono leading-[1.5]`}
        />
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
    <div id="runbooks" className="mb-[22px] scroll-mt-6">
      <div className="mb-1 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className="text-[15px] font-semibold">Runbooks</div>
          {onToggleCollapse && (
            <CollapseChevron collapsed={collapsed} onToggle={onToggleCollapse} label="Toggle Runbooks" />
          )}
        </div>
        {!collapsed && editing === null && (
          <button
            onClick={openNew}
            className="rounded-[7px] border border-border-strong bg-surface-3 px-[11px] py-[5px] text-[11.5px] font-semibold text-text hover:border-accent"
          >
            + New runbook
          </button>
        )}
      </div>
      {!collapsed && (
      <>
      <div className="mb-3 text-[12.5px] leading-[1.5] text-dim">
        Your team's own triage guidance. The investigation agent searches these (via the{' '}
        <code className="text-[11.5px] text-text">lookup_runbook</code> tool) and cites the best
        match — so it grounds a verdict in <strong>your</strong> procedures instead of guessing
        from thin data. A runbook that names a detection rule under{' '}
        <em>Linked rules</em> is preferred whenever that rule fires. Purely local — nothing here is
        ever written to Security Onion.
      </div>

      {editing === 'new' && <div className="mb-4">{form}</div>}

      <div className="overflow-hidden rounded-card border border-border bg-surface-1">
        {loading && <LoadingState />}
        {error && (
          <div className="p-3">
            <ErrorState error={error} />
          </div>
        )}
        {!loading && !error && runbooks.length === 0 && editing !== 'new' && (
          <div className="px-3.5 py-4 text-[12.5px] text-faint">
            No runbooks yet. Add one so the agent can cite your team's guidance.
          </div>
        )}
        {!loading &&
          !error &&
          runbooks.map((rb) => (
            <div
              key={rb.id}
              className="border-b border-border-faint px-3.5 py-3 last:border-b-0"
            >
              {editing === rb.id ? (
                form
              ) : (
                <div className="flex items-start gap-3">
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-[13px] font-medium" title={rb.title}>
                      {rb.title}
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
      </>
      )}
    </div>
  );
}
