import { AlertTriangle, Check, ChevronDown, ChevronRight, Loader2, Plus, Sparkles, X } from 'lucide-react';
import { useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';

import {
  MAX_OBJECTIVE_CHARS,
  createHuntTemplate,
  deleteHuntTemplate,
  getHuntTemplates,
  startHuntConsole,
  type HuntTemplate,
} from '../lib/api';
import { chipNotApplicable } from '../lib/tooltips';
import { useAsync } from '../lib/useAsync';
import { Drawer } from './Drawer';

// ---------------------------------------------------------------------------
// New hunt — the composer, in a drawer.
//
// The page grew by accretion: hits, leads, starters, composer, hunt list,
// schedules. The composer and its starters took the top of the page, above the
// work. Freeform hunting is one thing an analyst does, and it comes last, so it
// is one button at the top right of the Hunts section and a drawer behind it.
//
// The drawer holds the objective box, the starters, the template control and
// the Start hunt button. The page keeps nothing of it.
// ---------------------------------------------------------------------------

// Fallback pills — the seven canned hunts, used ONLY when the template API is
// unreachable or empty (a fresh store before the builtin seed). Normally the
// picker is fed by GET /hunt-templates (curated + availability-annotated). Kept
// in sync with the backend builtins (soc_ai/store/hunt_templates.py::_BUILTINS).
const FALLBACK_PRESETS: { label: string; objective: string }[] = [
  {
    label: 'Beaconing to rare IPs',
    objective:
      'Hunt for internal hosts that beacon to rare external IPs in the last 24 h. Look for a regular cadence, a low data volume and a novel destination. Use t_beacon_profile to measure the cadence. Use t_first_seen to find the novel destinations.',
  },
  {
    label: 'Credential abuse / lockouts',
    objective:
      'Hunt for credential abuse on the domain controllers. Look for account lockouts, failed-auth spikes and Kerberoasting.',
  },
  {
    label: 'Lateral movement',
    objective:
      'Hunt for lateral movement between internal hosts. Look for SMB admin-share access, PsExec style service creation and RDP.',
  },
  {
    label: 'DNS / C2 exfiltration',
    objective:
      'Hunt for DNS tunneling and C2 exfiltration. Look for high-entropy DNS, high-volume DNS, long TXT records and beaconing over DNS. Use t_dns_entropy_scan to measure the qname entropy and the volume.',
  },
  {
    label: 'New external services',
    objective:
      'Hunt for internal hosts that expose or reach a new external service this week. The host must never have used that service before. Use t_first_seen to compare the recent destinations against the baseline of 30 days.',
  },
  {
    label: 'Suspicious PowerShell / LOLBins',
    objective:
      'Hunt for suspicious PowerShell use on the endpoints. Include the living-off-the-land binaries.',
  },
  {
    label: 'DCE-RPC abuse / DC attacks',
    objective:
      'Hunt for attacks on a domain controller in DCE-RPC. Look for Zerologon style NetrServerAuthenticate floods, DCSync calls to DRSGetNCChanges and remote service creation. Use t_dcerpc_histogram first. Investigate every flagged operation and every rare dangerous operation.',
  },
];

// ---------------------------------------------------------------------------
// Template picker — curated hunt starters annotated on TWO independent axes
// (E3.2 + hunt-fit). Fed by GET /hunt-templates: each chip fills the objective
// box (like the old static pills). Three states, three operator actions:
//   · available + applicable → normal accent chip ("the telemetry is here").
//   · missing telemetry (available=false) → amber flag + "missing telemetry:
//     zeek.rdp" — a FIXABLE collection gap.
//   · availability UNKNOWN (availabilityKnown=false — the server could not read
//     the grid inventory, so `available` is a fail-open default and not a
//     measurement) → neutral gray chip, no glyph, one caption for the strip.
//     Deliberately unlike the amber state: "we looked and the telemetry is
//     missing" and "we could not look" are different facts and must not share a
//     colour. What they must NOT share is the accent chip, which asserts the
//     grid is seeing this telemetry — that assertion is how an analyst came to
//     launch a hunt against data a half-read grid could not read.
//   · not applicable (applicable=false — the network shows none of the
//     machinery the hunt targets, e.g. Kerberoasting with no domain) → DEMOTED
//     into a collapsed "Not applicable here" cluster at the end of the strip,
//     grayed, never hidden, still runnable. The server recomputes fit per
//     request from the dossier store, and this picker polls every 60s, so the
//     first observed domain join reopens the hunt on its own.
// Clicking any chip still fills the box (the operator may want to see the
// objective, or knows the data is coming). Falls back to the six static pills
// when the template API is unreachable/empty so the picker never disappears.
// An admin can save a modest custom template inline.
// ---------------------------------------------------------------------------
function TemplatePicker({
  onPick,
}: {
  onPick: (objective: string, template?: { id: number; analytics?: string[] }) => void;
}) {
  const [reloadKey, setReloadKey] = useState(0);
  const { data, error } = useAsync<HuntTemplate[]>(getHuntTemplates, [reloadKey], {
    // Amber (missing telemetry) and demotion (environment fit) must clear on
    // their own once the grid or the dossier sweep catches up — the server side
    // is TTL-cached (300s inventory) so a 60s poll is cheap, and worst-case
    // staleness becomes TTL+interval instead of "until the operator reloads".
    refetchInterval: 60_000,
  });
  // The not-applicable cluster's expand state (collapsed by default — demoted,
  // not hidden).
  const [showDemoted, setShowDemoted] = useState(false);

  // Inline "add custom template" form (collapsed by default — modest, like the
  // schedule editor). builtin templates are code-owned; customs are operator-saved.
  const [adding, setAdding] = useState(false);
  const [name, setName] = useState('');
  const [objective, setObjective] = useState('');
  const [datasets, setDatasets] = useState('');
  const [busy, setBusy] = useState(false);
  const [formErr, setFormErr] = useState<string | null>(null);

  const resetForm = () => {
    setName('');
    setObjective('');
    setDatasets('');
    setFormErr(null);
    setAdding(false);
  };

  const saveCustom = async () => {
    const nm = name.trim();
    const obj = objective.trim();
    if (!nm || !obj || busy) return;
    const required = datasets
      .split(',')
      .map((d) => d.trim())
      .filter(Boolean);
    setBusy(true);
    setFormErr(null);
    try {
      await createHuntTemplate({ name: nm, objective_template: obj, required_datasets: required });
      resetForm();
      setReloadKey((k) => k + 1);
    } catch (e: unknown) {
      setFormErr(e instanceof Error ? e.message : 'Could not save the starter.');
    } finally {
      setBusy(false);
    }
  };

  const removeCustom = async (id: number) => {
    try {
      await deleteHuntTemplate(id);
    } catch {
      /* 409 on a builtin / admin-gated / transient — the next load reflects reality */
    }
    setReloadKey((k) => k + 1);
  };

  // Fallback to the static pills when the template API is unreachable or the
  // store is empty (fresh install, pre-seed) — the picker must never vanish.
  const templates = data ?? [];
  const useFallback = !!error || templates.length === 0;

  // `!== false` rather than a truthiness check is the fail-open half: the field
  // is optional on HuntTemplate, so a payload from a server predating it reads
  // as "known", which is what it was.
  const availabilityKnown = (t: HuntTemplate): boolean => t.availabilityKnown !== false;
  // One unreadable inventory annotates the whole strip — the server evaluates
  // the axis once for the list, so this is never mixed.
  const fitUnknown = !useFallback && templates.some((t) => !availabilityKnown(t));

  // The two-axis split: applicable chips render inline (normal or amber);
  // not-applicable ones cluster at the end, collapsed. `!== false` keeps a
  // payload without the field (older server) on the inline path — fail open.
  const applicableTemplates = templates.filter((t) => t.applicable !== false);
  const demoted = templates.filter((t) => t.applicable === false);

  const demotedTitle = (t: HuntTemplate): string => {
    const needs = t.missingEnvironment.length
      ? t.missingEnvironment.join(' and ')
      : 'machinery that this network has not shown';
    const runsFirst =
      t.analytics && t.analytics.length > 0 ? `\n\nRuns first: ${t.analytics.join(', ')}.` : '';
    return (
      `${t.objectiveTemplate}\n\nThis hunt needs ${needs}. The network shows none of it. ` +
      'Each dossier sweep checks this again. You can still run this hunt.' +
      runsFirst
    );
  };

  return (
    <div className="mb-2">
      <div className="flex flex-wrap items-center gap-1.5">
        <span className="mr-0.5 text-[10.5px] font-semibold uppercase tracking-[.06em] text-faint">
          Starters
        </span>
        {useFallback
          ? FALLBACK_PRESETS.map((p) => (
              <button
                key={p.label}
                type="button"
                onClick={() => onPick(p.objective)}
                title={p.objective}
                className="rounded-badge border border-border-strong bg-surface-2 px-[9px] py-[3px] text-[11.5px] font-medium text-dim transition-colors hover:border-accent hover:text-accent"
              >
                {p.label}
              </button>
            ))
          : applicableTemplates.map((t) => {
              // Three states, and `unknown` is checked FIRST: when the server
              // could not read the inventory it reports every template
              // available, so asking `!t.available` alone can only ever produce
              // the confident answer.
              const unknown = !availabilityKnown(t);
              const flagged = !unknown && !t.available;
              // A requirement that names alternatives ("zeek.rdp|system.security")
              // is missing as a whole; read it back as "either … or …".
              const missing = t.missingDatasets.map((m) => m.split('|').join(' or ')).join(', ');
              // Present only as imported history: still available, and said so.
              const backfill = (t.backfillOnlyDatasets ?? [])
                .map((m) => m.split('|').join(' or '))
                .join(', ');
              const backfillNote = backfill
                ? `\n\nBackfill only: ${backfill}. The grid holds this data. No sensor here produces it now. This hunt reads history.`
                : '';
              // The analytics this starter runs before the hunt itself, named
              // in the tooltip so the analyst knows what "Start hunt" is about
              // to do — a second sentence, not a replacement for the first.
              const runsFirst =
                t.analytics && t.analytics.length > 0
                  ? `\n\nRuns first: ${t.analytics.join(', ')}.`
                  : '';
              const title =
                (unknown
                  ? `${t.objectiveTemplate}\n\nThe availability is unknown. The grid inventory could not be read. This starter is unchecked against live telemetry.`
                  : flagged
                    ? `${t.objectiveTemplate}\n\n⚠ missing telemetry: ${missing}`
                    : `${t.objectiveTemplate}${backfillNote}`) + runsFirst;
              return (
                <span key={t.id} className="inline-flex items-center">
                  <button
                    type="button"
                    onClick={() => onPick(t.objectiveTemplate, { id: t.id, analytics: t.analytics })}
                    title={title}
                    // The state is in the DOM, not only in a class name: it is
                    // the contract the picker is tested against, and "no chip
                    // claims availability" is otherwise an assertion about
                    // Tailwind strings.
                    data-availability={unknown ? 'unknown' : flagged ? 'missing' : 'available'}
                    data-backfill={backfill ? 'true' : undefined}
                    className={
                      unknown
                        ? 'flex items-center gap-1 rounded-badge border border-border-strong bg-surface-2 px-[9px] py-[3px] text-[11.5px] font-medium text-dim transition-colors hover:border-accent hover:text-accent'
                        : flagged
                          ? 'flex items-center gap-1 rounded-badge border border-warn/40 bg-warn/5 px-[9px] py-[3px] text-[11.5px] font-medium text-warn/80 opacity-70 transition-opacity hover:opacity-100'
                          : 'flex items-center gap-1 rounded-badge border border-accent/40 bg-accent/5 px-[9px] py-[3px] text-[11.5px] font-medium text-accent transition-colors hover:border-accent hover:bg-accent/10'
                    }
                  >
                    {flagged && <AlertTriangle size={11} className="flex-none" />}
                    {t.name}
                  </button>
                  {!t.builtin && (
                    <button
                      type="button"
                      onClick={() => { void removeCustom(t.id); }}
                      title="Delete this starter"
                      className="ml-0.5 flex text-faint hover:text-danger"
                    >
                      <X size={11} />
                    </button>
                  )}
                </span>
              );
            })}
        {/* Not-applicable cluster — demoted, never hidden. Grayed (muted
            border/text, no warn color: nothing here is broken or fixable, the
            network just hasn't shown the machinery), each chip still fills the
            objective box exactly like an inline one. */}
        {!useFallback && demoted.length > 0 && (
          <button
            type="button"
            onClick={() => setShowDemoted((v) => !v)}
            title={chipNotApplicable(demoted.length)}
            className="flex items-center gap-1 rounded-badge border border-dashed border-border-strong bg-transparent px-[9px] py-[3px] text-[11px] font-medium text-faint transition-colors hover:text-dim"
          >
            {showDemoted ? <ChevronDown size={11} /> : <ChevronRight size={11} />}
            Not applicable here · {demoted.length}
          </button>
        )}
        {!useFallback &&
          showDemoted &&
          demoted.map((t) => (
            <span key={t.id} className="inline-flex items-center">
              <button
                type="button"
                onClick={() => onPick(t.objectiveTemplate, { id: t.id, analytics: t.analytics })}
                title={demotedTitle(t)}
                className="flex items-center gap-1 rounded-badge border border-border bg-surface-2 px-[9px] py-[3px] text-[11.5px] font-medium text-faint opacity-70 transition-opacity hover:opacity-100"
              >
                {t.name}
              </button>
            </span>
          ))}
        {/* add-custom toggle */}
        <button
          type="button"
          onClick={() => setAdding((v) => !v)}
          title="Save a starter of your own. It joins the chips above."
          className="flex items-center gap-1 rounded-badge border border-dashed border-border-strong bg-transparent px-[9px] py-[3px] text-[11.5px] font-medium text-faint transition-colors hover:border-accent hover:text-accent"
        >
          <Plus size={11} /> Starter
        </button>
      </div>

      {/* legend — only when at least one INLINE template is unavailable
          (nothing to contrast otherwise; the collapsed cluster explains
          itself). Positive framing: the highlighted ones are the runnable
          ones; the AlertTriangle stays on the unavailable chips only. It is
          gated on `!fitUnknown` because the claim it makes ("these match live
          telemetry") is exactly the one an unread inventory cannot support. */}
      {!useFallback && !fitUnknown && applicableTemplates.some((t) => !t.available) && (
        <div className="mt-1.5 text-[10.5px] text-accent/80">
          The highlighted starters match the telemetry this grid sees.
        </div>
      )}

      {/* The template list LOADED, but the server could not read the grid
          inventory to annotate it — the half-read-grid case, where every chip
          came back available because that is what fail-open means. Say the axis
          is unevaluated rather than let six confident chips imply it passed. */}
      {fitUnknown && (
        <div className="mt-1.5 text-[10.5px] text-faint">
          The availability is unknown. The grid inventory could not be read. These starters are
          unchecked against live telemetry.
        </div>
      )}

      {/* Fallback pills carry NO annotation (neither axis is knowable without
          the template service) — say so once, muted, instead of per-pill. */}
      {useFallback && !!error && (
        <div className="mt-1.5 text-[10.5px] text-faint">
          The availability is unknown. The list of starters could not be read.
        </div>
      )}

      {/* inline custom-template form */}
      {adding && (
        <div className="mt-2 flex flex-wrap items-center gap-2 rounded-control border border-border bg-surface-2 px-3 py-2">
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Starter name"
            className="min-w-[140px] flex-none rounded-control border border-border-input bg-bg px-2.5 py-1.5 text-[12px] text-text outline-none focus:border-accent"
          />
          <input
            value={objective}
            onChange={(e) => setObjective(e.target.value)}
            placeholder="The objective the chip loads…"
            className="min-w-[220px] flex-1 rounded-control border border-border-input bg-bg px-2.5 py-1.5 text-[12px] text-text outline-none focus:border-accent"
          />
          <input
            value={datasets}
            onChange={(e) => setDatasets(e.target.value)}
            placeholder="Required datasets, comma separated. Example: zeek.dns"
            className="min-w-[180px] flex-none rounded-control border border-border-input bg-bg px-2.5 py-1.5 text-[12px] text-text outline-none focus:border-accent"
          />
          <button
            type="button"
            onClick={() => { void saveCustom(); }}
            disabled={!name.trim() || !objective.trim() || busy}
            className="flex items-center gap-1 rounded-control bg-accent px-3 py-1.5 text-[12px] font-semibold text-white hover:bg-accent-deep disabled:cursor-not-allowed disabled:opacity-50"
          >
            {busy ? <Loader2 size={12} className="animate-spin" /> : <Check size={12} />} Save
          </button>
          <button
            type="button"
            onClick={resetForm}
            className="rounded-control border border-border-strong bg-bg px-3 py-1.5 text-[12px] font-semibold text-dim hover:text-text"
          >
            Cancel
          </button>
          {formErr && <div className="w-full text-[11.5px] text-danger">{formErr}</div>}
        </div>
      )}
    </div>
  );
}

export function NewHuntDrawer({ onClose }: { onClose: () => void }) {
  const navigate = useNavigate();
  const [objective, setObjective] = useState('');
  // The starter a chip picked, if any. Sent as `startHuntConsole`'s third
  // argument so the server can run the starter's analytics first. Cleared the
  // moment the analyst edits the text by hand: a hand-edited objective is no
  // longer the starter's objective, so it should not run the starter's
  // analytics.
  const [pickedTemplateId, setPickedTemplateId] = useState<number | null>(null);
  const [starting, setStarting] = useState(false);
  const [startError, setStartError] = useState<string | null>(null);
  const objectiveRef = useRef<HTMLTextAreaElement | null>(null);

  const launch = () => {
    const obj = objective.trim();
    if (!obj || starting) return;
    setStarting(true);
    setStartError(null);
    startHuntConsole(obj, undefined, pickedTemplateId ?? undefined)
      .then((r) => {
        setObjective('');
        setPickedTemplateId(null);
        navigate(`/hunts/${r.hunt_id}`);
      })
      .catch((e: unknown) => {
        setStartError(e instanceof Error ? e.message : 'Could not start the hunt.');
      })
      .finally(() => setStarting(false));
  };

  return (
    <Drawer
      open
      onClose={onClose}
      header={
        <div className="flex min-w-0 flex-1 items-center justify-between gap-2.5">
          <span className="text-[13.5px] font-semibold">New hunt</span>
          <button
            type="button"
            onClick={onClose}
            className="rounded-control border border-border-strong px-2.5 py-1 text-[12px] font-semibold text-dim hover:text-text"
          >
            Close
          </button>
        </div>
      }
    >
      <div className="flex h-full flex-col">
        <div className="flex-1 overflow-y-auto p-4">
          <div className="mb-1.5 text-[10.5px] font-semibold uppercase tracking-[.06em] text-faint">
            Objective
          </div>
          <div className="relative">
            <Sparkles
              size={15}
              className="pointer-events-none absolute left-[11px] top-[10px] text-accent"
            />
            <textarea
              ref={objectiveRef}
              autoFocus
              value={objective}
              onChange={(e) => {
                setObjective(e.target.value);
                setPickedTemplateId(null);
              }}
              onKeyDown={(e) => {
                // Enter starts the hunt, Shift+Enter breaks the line. A
                // multi-line brief needs a way to break lines without
                // launching (dogfood 2026-08-06).
                if (e.key === 'Enter' && !e.shiftKey) {
                  e.preventDefault();
                  launch();
                }
              }}
              rows={4}
              maxLength={MAX_OBJECTIVE_CHARS}
              placeholder="Describe a hunt in plain language. Example: hunt for beaconing to rare external IPs, or credential-abuse lockouts on the DCs."
              className="w-full resize-y overflow-y-auto rounded-control border border-border-input bg-bg py-2 pl-9 pr-3 text-[13px] leading-[20px] text-text outline-none focus:border-accent"
            />
          </div>
          <div className="mt-1.5 text-[11px] text-faint">
            The agent correlates across the hosts and the time range. It reports findings and a
            narrative. The agent is read-only. Press Shift+Enter for a new line. A detailed brief
            gets a better hunt. Name the scope, the exclusions and the behaviors.
          </div>
          {objective.length > MAX_OBJECTIVE_CHARS * 0.8 && (
            <div className="mt-1 text-right text-[11px] text-faint">
              {objective.length.toLocaleString()} / {MAX_OBJECTIVE_CHARS.toLocaleString()} characters
            </div>
          )}

          <div className="mt-4">
            {/* Curated hunt templates — a chip loads a high-payoff objective,
                then the analyst edits the scope and starts it. */}
            <TemplatePicker
              onPick={(obj, template) => {
                setObjective(obj);
                setPickedTemplateId(template?.id ?? null);
                setStartError(null);
                objectiveRef.current?.focus();
              }}
            />
          </div>
          {startError && <div className="mt-2 text-[12px] text-danger">{startError}</div>}
        </div>

        <div className="flex flex-none flex-wrap items-center gap-3 border-t border-border px-4 py-3">
          <button
            onClick={launch}
            disabled={!objective.trim() || starting}
            className="flex flex-none items-center gap-1.5 rounded-control bg-accent px-[15px] py-2 text-[13px] font-semibold text-white hover:bg-accent-deep disabled:cursor-not-allowed disabled:opacity-50"
          >
            {starting ? <Loader2 size={15} className="animate-spin" /> : <Plus size={15} />}
            {starting ? 'Starting…' : 'Start hunt'}
          </button>
          <span className="text-[11.5px] text-faint">
            The hunt starts at once. It appears in the hunt list as Running.
          </span>
        </div>
      </div>
    </Drawer>
  );
}
