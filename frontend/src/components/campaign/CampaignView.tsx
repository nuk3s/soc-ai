import { useEffect, useRef, useState } from 'react';
import type { CampaignDetail } from '../../lib/api';
import { useSession } from '../../shell/Session';
import { AttackGraph } from './AttackGraph';
import { AuthorizeCampaignDialog } from './AuthorizeCampaignDialog';
import {
  BEYOND_TITLE,
  EXCLUDED_TITLE,
  LEADS_HUNTS_TITLE,
  alertsFoldDetail,
  heldInvestigations,
  lastActivityOf,
  leadsHuntsDetail,
  showingNewWords,
  sinceBandWords,
} from '../../lib/campaignWords';
import { CampaignAlerts, distinctRules } from './CampaignAlerts';
import { CampaignBeyond } from './CampaignBeyond';
import { CampaignChanges } from './CampaignChanges';
import { CampaignExcluded } from './CampaignExcluded';
import { CampaignFindings, findingRows } from './CampaignFindings';
import { CampaignHeader } from './CampaignHeader';
import { CampaignLeadsHunts } from './CampaignLeadsHunts';
import { CampaignMembers } from './CampaignMembers';
import { CampaignParties } from './CampaignParties';
import { CampaignRelated } from './CampaignRelated';
import { CampaignTimeline } from './CampaignTimeline';
import { CampaignVerdictsDiffer } from './CampaignVerdictsDiffer';
import { CloseCampaignDialog } from './CloseCampaignDialog';
import { DetectionRecord } from './DetectionRecord';
import { Fold } from './Fold';
import { OpenCaseDialog } from './OpenCaseDialog';
import { StageLadder } from './StageLadder';
import type { CampaignSelection } from './selection';

type FoldName =
  | 'beyond'
  | 'alerts'
  | 'findings'
  | 'leadsHunts'
  | 'machines'
  | 'related'
  | 'differ'
  | 'detection'
  | 'investigations'
  | 'excluded'
  | 'changes';

/** One campaign, graphical first: the stage ladder, the attack graph and the
 *  timeline state the campaign. The folds under them hold the tables. The
 *  first fold lists the investigations beyond the authorization, the one
 *  alarm of an authorized campaign, and it starts open. Each other fold
 *  starts closed: the alerts, the findings, the leads and the hunts, the
 *  machines, the related candidates, the verdicts that differ, the detection record, the
 *  investigations and the changes of the campaign. A fold with nothing to
 *  show does not render.
 *
 *  A machine or an arrow picked on the attack graph opens the Alerts fold. A
 *  mark picked on the timeline opens the Investigations fold. The page then
 *  scrolls the fold into view. With no Alerts fold, a machine or an arrow
 *  opens the Investigations fold. A cleared pick leaves the fold open. */
export function CampaignView({
  campaign,
  onDecided = () => {},
}: {
  campaign: CampaignDetail;
  /** A close, a case or an Open again landed: the answer is the campaign after it. */
  onDecided?: (next: CampaignDetail) => void;
}) {
  const [closing, setClosing] = useState(false);
  const [authorizing, setAuthorizing] = useState(false);
  const [casing, setCasing] = useState(false);
  // The server holds the admin rule. A session the console cannot read keeps
  // the button, as the dialog of an investigation does.
  const { me } = useSession();
  const canAuthorize = !me || me.role === 'admin';
  const [selection, setSelection] = useState<CampaignSelection | null>(null);
  const [target, setTarget] = useState<FoldName | null>(null);
  // True while the table shows only the investigations that are new since
  // the earlier decision (SD3).
  const [newOnly, setNewOnly] = useState(false);
  // The fold of the investigations beyond the authorization is the one alarm
  // of an authorized campaign, so it starts open.
  const [open, setOpen] = useState<Record<FoldName, boolean>>({
    beyond: true,
    alerts: false,
    findings: false,
    leadsHunts: false,
    machines: false,
    related: false,
    differ: false,
    detection: false,
    investigations: false,
    excluded: false,
    changes: false,
  });
  const alertsRef = useRef<HTMLDivElement>(null);
  const beyondRef = useRef<HTMLDivElement>(null);
  const investigationsRef = useRef<HTMLDivElement>(null);
  const d = campaign;
  const closed = d.status === 'merged' || d.status === 'withdrawn';
  // A server of an earlier release sends no events.
  const pairs = d.events?.pairs ?? [];
  const rules = distinctRules(pairs);
  const findings = findingRows(d.members).length;

  const toggle = (name: FoldName) => setOpen((o) => ({ ...o, [name]: !o[name] }));
  const select = (next: CampaignSelection | null) => {
    setSelection(next);
    if (!next) return;
    setNewOnly(false);
    const fold: FoldName = next.kind !== 'runs' && rules > 0 ? 'alerts' : 'investigations';
    setTarget(fold);
    setOpen((o) => (o[fold] ? o : { ...o, [fold]: true }));
  };
  // The effect runs after the render that opened the fold, so the scroll
  // reaches the table. A runtime with no scrollIntoView skips the scroll.
  useEffect(() => {
    if (!selection || !target) return;
    const el = (target === 'alerts' ? alertsRef : investigationsRef).current;
    if (el && typeof el.scrollIntoView === 'function') {
      el.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    }
  }, [selection, target]);
  // The control "Show the new investigations" opens the fold; the effect runs
  // after the render that opened it, so the scroll reaches the table.
  useEffect(() => {
    if (!newOnly) return;
    const el = investigationsRef.current;
    if (el && typeof el.scrollIntoView === 'function') el.scrollIntoView({ block: 'start', behavior: 'smooth' });
  }, [newOnly]);

  const memberRows = heldInvestigations(d.members);
  const differ = d.members.length - memberRows;
  const { needsMoreInfo, sessions, named, falsePositiveFromTargets } = d.related;
  // The false positive line is a count of alerts that are no candidates, so
  // it adds nothing to the count of the fold. It still opens the fold.
  // An earlier server sends no leads and no hunts.
  const leads = d.leads ?? [];
  const hunts = d.hunts ?? [];
  const ownLeads = leads.filter((l) => !l.related).length;
  const relatedLeads = leads.length - ownLeads;
  const relatedCount = needsMoreInfo.length + relatedLeads + sessions.length + named.length;
  const hasRelated = relatedCount > 0 || falsePositiveFromTargets > 0;
  const clear = () => setSelection(null);
  const beyond = d.beyond ?? [];
  const excluded = d.excluded ?? [];
  // A server of an earlier release has no route for Exclude and Include: it
  // sends no list of excluded investigations, so the rows offer no write.
  const writes = d.excluded !== undefined ? { campaignId: d.id, onChanged: onDecided } : undefined;
  const outsideIds = new Set(beyond.map((b) => b.runId));
  const labels = Object.fromEntries(
    [...d.members, ...beyond, ...excluded, ...d.related.needsMoreInfo].map((r) => [r.runId, r.label]),
  );
  // The investigations that are new since the earlier decision, from the
  // one reader of the server. The control opens exactly these rows.
  const since = d.sinceDecision ?? null;
  const fresh = new Set(since?.runIds ?? []);
  const showNew = () => {
    setSelection(null);
    setNewOnly(true);
    setOpen((o) => (o.investigations ? o : { ...o, investigations: true }));
  };
  const showBeyond = () => {
    setOpen((o) => (o.beyond ? o : { ...o, beyond: true }));
    const el = beyondRef.current;
    if (el && typeof el.scrollIntoView === 'function') el.scrollIntoView({ block: 'start', behavior: 'smooth' });
  };

  return (
    <div data-testid="campaign-view" className="flex flex-col gap-4">
      <CampaignHeader
        campaign={d}
        onCloseRequest={() => setClosing(true)}
        onDecided={onDecided}
        onAuthorizeRequest={() => setAuthorizing(true)}
        onCaseRequest={() => setCasing(true)}
        canAuthorize={canAuthorize}
        onShowBeyond={beyond.length > 0 ? showBeyond : undefined}
        onShowNew={fresh.size > 0 ? showNew : undefined}
      />
      <CloseCampaignDialog campaign={d} open={closing} onClose={() => setClosing(false)} onClosed={onDecided} />
      <AuthorizeCampaignDialog
        campaign={d}
        open={authorizing}
        onClose={() => setAuthorizing(false)}
        onAuthorized={onDecided}
      />
      <OpenCaseDialog campaign={d} open={casing} onClose={() => setCasing(false)} onOpened={onDecided} />
      {!closed && (
        <>
          <StageLadder ladder={d.ladder} />
          <AttackGraph
            parties={d.parties}
            edges={d.graph?.edges ?? []}
            related={d.related}
            members={d.members}
            pairs={pairs}
            selection={selection}
            onSelect={select}
            authorization={d.authorization}
            outside={beyond}
          />
          <CampaignTimeline
            events={d.events}
            members={d.members}
            parties={d.parties}
            ladder={d.ladder}
            changes={d.changes}
            authorization={d.authorization}
            selection={selection}
            onSelect={select}
            answer={d.answers?.[0] ?? null}
            since={since ? { boundary: since.boundary, words: sinceBandWords(since) } : null}
          />
          {beyond.length > 0 && (
            <Fold
              title={BEYOND_TITLE}
              count={beyond.length}
              open={open.beyond}
              onToggle={() => toggle('beyond')}
              testId="fold-beyond"
              foldRef={beyondRef}
              tone="danger"
            >
              <CampaignBeyond beyond={beyond} parties={d.parties} />
            </Fold>
          )}
          {rules > 0 && (
            <Fold
              title="Alerts"
              count={null}
              detail={alertsFoldDetail(d.events)}
              open={open.alerts}
              onToggle={() => toggle('alerts')}
              testId="fold-alerts"
              foldRef={alertsRef}
            >
              <CampaignAlerts pairs={pairs} parties={d.parties} selection={selection} onClearSelection={clear} />
            </Fold>
          )}
          {findings > 0 && (
            <Fold
              title="Findings"
              count={findings}
              open={open.findings}
              onToggle={() => toggle('findings')}
              testId="fold-findings"
            >
              <CampaignFindings members={d.members} />
            </Fold>
          )}
          {(ownLeads > 0 || hunts.length > 0) && (
            <Fold
              title={LEADS_HUNTS_TITLE}
              count={null}
              detail={leadsHuntsDetail(ownLeads, hunts.length)}
              open={open.leadsHunts}
              onToggle={() => toggle('leadsHunts')}
              testId="fold-leads-hunts"
            >
              <CampaignLeadsHunts
                leads={leads}
                hunts={hunts}
                changes={d.changes ?? []}
                firstEvent={d.firstEvent}
                lastEvent={lastActivityOf(d)}
              />
            </Fold>
          )}
          {d.parties.length > 0 && (
            <Fold
              title="Machines"
              count={d.parties.length}
              open={open.machines}
              onToggle={() => toggle('machines')}
              testId="fold-machines"
            >
              <CampaignParties parties={d.parties} embedded />
            </Fold>
          )}
          {hasRelated && (
            <Fold
              title="Related, not proven"
              // The fold can hold only the line of the false positive alerts: it then states no count.
              count={relatedCount > 0 ? relatedCount : null}
              open={open.related}
              onToggle={() => toggle('related')}
              testId="fold-related"
            >
              <CampaignRelated related={d.related} leads={leads} embedded writes={writes} />
            </Fold>
          )}
          {differ > 0 && (
            <Fold
              title="Verdicts that differ"
              count={differ}
              open={open.differ}
              onToggle={() => toggle('differ')}
              testId="fold-differ"
            >
              <CampaignVerdictsDiffer members={d.members} embedded />
            </Fold>
          )}
          {d.detection.length > 0 && (
            <Fold
              title="Detection record"
              count={null}
              open={open.detection}
              onToggle={() => toggle('detection')}
              testId="fold-detection"
            >
              <DetectionRecord detection={d.detection} embedded />
            </Fold>
          )}
          {(memberRows > 0 || (newOnly && fresh.size > 0)) && (
            <Fold
              title="Investigations"
              count={memberRows}
              open={open.investigations}
              onToggle={() => toggle('investigations')}
              testId="fold-investigations"
              foldRef={investigationsRef}
            >
              <CampaignMembers
                members={d.members}
                parties={d.parties}
                selection={selection}
                onClearSelection={clear}
                embedded
                writes={writes ? { ...writes, outside: outsideIds } : undefined}
                fresh={fresh}
                newOnly={newOnly && fresh.size > 0}
                newWords={since ? showingNewWords(since) : undefined}
                onShowAll={() => setNewOnly(false)}
              />
            </Fold>
          )}
          {writes && excluded.length > 0 && (
            <Fold
              title={EXCLUDED_TITLE}
              count={excluded.length}
              open={open.excluded}
              onToggle={() => toggle('excluded')}
              testId="fold-excluded"
            >
              <CampaignExcluded excluded={excluded} campaignId={d.id} onChanged={onDecided} />
            </Fold>
          )}
          {(d.changes?.length ?? 0) > 0 && (
            <Fold
              title="Changes"
              count={d.changes?.length ?? 0}
              open={open.changes}
              onToggle={() => toggle('changes')}
              testId="fold-changes"
            >
              <CampaignChanges changes={d.changes ?? []} labels={labels} />
            </Fold>
          )}
        </>
      )}
    </div>
  );
}
