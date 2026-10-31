// ---------------------------------------------------------------------------
// Every tour of the console, in one module, so the owner reviews all tour text
// in one place.
//
// Rules for the text (ASD-STE100, see CLAUDE.md). content.test.ts checks the
// mechanical ones:
// - A title is a plain noun phrase: "Page time filter", "Waiting actions".
// - A body is one to three sentences. One topic per sentence. At most 20 words
//   in an instruction and 25 in a description. Active voice, present tense.
// - No em or en dash, no parenthetical aside, no exclamation mark, no "not X
//   but Y", "rather than", "instead of", "simply", "just", "easily".
// - The product terms: analytic, observation, lead, hunt, verdict, alert,
//   grid, store, sweep, dossier, profile, baseline, departure, finding,
//   investigation, the model, the Oracle, the console, the operator, the
//   analyst. The user-facing word is "type", never "kind". The settings page
//   is "Settings". The status page is "Status".
//
// Each step names a `data-tour` anchor on a real element. A step whose anchor
// is not on the page is skipped. Each page tour has a smoke test that renders
// its screen and checks every anchor it names.
//
// Versions: bump a tour's version only when it changes in a way a returning
// operator needs to see. The tour then starts again on the next visit.
// ---------------------------------------------------------------------------
import { matchPath } from 'react-router-dom';
import type { Tour } from './types';

// ── The welcome tour ─────────────────────────────────────────────────────────
// The first sign-in, or the first visit with authentication off. Six steps at
// most, all on the shell except the page time filter.

export const WELCOME_TOUR: Tour = {
  id: 'welcome',
  version: 1,
  name: 'soc-ai',
  routes: [],
  steps: [
    {
      anchor: 'nav',
      title: 'Sidebar',
      body:
        'The sidebar opens every page of the console. ' +
        'A badge beside a page counts the items on that page that need you.',
      placement: 'right',
    },
    {
      anchor: 'time-filter',
      title: 'Page time filter',
      body:
        'This filter sets the time window of the page. ' +
        'Every count and every list on the page uses this window. ' +
        'An item with a different window states its own window.',
      scope: 'page',
    },
    {
      anchor: 'search',
      title: 'Search',
      body:
        'Search opens a page, a host, an alert group, an investigation, a hunt, a user or a domain. ' +
        'It also finds a setting and runs commands. ' +
        'The shortcut is Ctrl K, or ⌘K on a Mac.',
    },
    {
      anchor: 'bell',
      title: 'Notifications',
      body:
        'The badge counts the items that need you. ' +
        'These are alert groups with no verdict, verdicts that need more information, waiting actions, open leads and unread shadow hits. ' +
        'The panel also lists events, such as a finished hunt.',
    },
    {
      anchor: 'ask',
      title: 'Ask soc-ai',
      body:
        'The chat sends your question to the model. ' +
        'On a record page, the chat has that record in scope. ' +
        'The shortcut is C.',
    },
    {
      anchor: 'help',
      title: 'Help menu',
      body:
        'This menu opens the tour of the current page, the keyboard shortcuts and the guide. ' +
        'Each page shows its tour one time, on the first visit.',
    },
  ],
};

// ── Page tours ───────────────────────────────────────────────────────────────

// One definition of a grid gap for every page that shows the gap strip.
const GRID_GAP = 'A grid gap is a time with missing data in the grid. ';
// One tour per page. Each block below holds one tour. Keep the BEGIN and END
// markers: they keep each tour in one place for review.

// ── BEGIN tour: dashboard ──
export const DASHBOARD_TOUR: Tour = {
  id: 'dashboard',
  version: 1,
  name: 'Dashboard',
  routes: ['/dashboard'],
  steps: [
    {
      anchor: 'dashboard-header',
      title: 'Dashboard',
      body:
        'The Dashboard shows the current activity of the grid and the verdicts of soc-ai. ' +
        'The line under the title names the window of the counts.',
    },
    {
      anchor: 'time-filter',
      title: 'Page time filter',
      body:
        'This filter sets the window of the counts, the chart and the recent investigations. ' +
        'A tile with a different scope states that scope in its text.',
    },
    {
      anchor: 'grid-gap',
      title: 'Grid gaps',
      body:
        'This strip names each grid gap in the page window. ' +
        GRID_GAP +
        'The counts of the window are incomplete.',
    },
    {
      anchor: 'dashboard-needs-you',
      title: 'Needs you',
      body:
        'This tile counts the work that waits on you. ' +
        'Each line states its scope and opens the list that holds the work. ' +
        'The bell in the top bar shows the same total.',
    },
    {
      anchor: 'dashboard-outcomes',
      title: 'Investigation outcomes',
      body:
        'The chart counts the alert groups of the window by verdict and by severity. ' +
        'A verdict tile or a severity bar opens the Alerts list with the same filter and window.',
    },
    {
      anchor: 'dashboard-recent',
      title: 'Recent investigations',
      body:
        'This list shows the newest investigations of the window. ' +
        'The name of a row opens the investigation. ' +
        'View all opens the Investigations list on the same window.',
    },
    {
      anchor: 'dashboard-setup-health',
      title: 'Setup health',
      body:
        'This card shows the result of the setup checks. ' +
        'An admin sees the name of each check that fails or warns. ' +
        'Re-check runs the checks now and ignores the 10 minute cache.',
    },
  ],
};
// ── END tour: dashboard ──

// ── BEGIN tour: alerts ──
export const ALERTS_TOUR: Tour = {
  id: 'alerts',
  version: 1,
  name: 'Alerts',
  routes: ['/alerts'],
  steps: [
    {
      anchor: 'alerts-header',
      title: 'Alerts',
      body:
        'This page lists the alerts of Security Onion in groups, one group for each detection. ' +
        'Bulk Investigate starts investigations of the alerts of the last 24 hours at the chosen severity or higher. ' +
        'The page time filter does not change this window.',
    },
    {
      anchor: 'time-filter',
      title: 'Page time filter',
      body:
        'This filter sets the time window of the list and of the counts on the page. ' +
        'The Severity, Verdict and Hide acknowledged filters beside it narrow the list. ' +
        'Hide acknowledged is on by default.',
    },
    {
      anchor: 'grid-gap',
      title: 'Grid gaps',
      body:
        'This strip names each grid gap in the page window. ' +
        GRID_GAP +
        'The counts of the window are incomplete.',
    },
    {
      anchor: 'alerts-row',
      title: 'Alert group',
      body:
        'Each row is one detection with its alerts in the page window. ' +
        'The soc-ai verdict column shows the worst verdict among the investigations in the window. ' +
        'Click the row to show its events.',
    },
    {
      anchor: 'alerts-select',
      title: 'Group selection',
      body:
        'Select the check box of a row to show the bar of group actions under the filters. ' +
        'Acknowledge writes to Security Onion with no confirm. ' +
        'Escalate to cases asks first and states how many cases it opens.',
    },
    {
      anchor: 'alerts-row-actions',
      title: 'Row actions',
      body:
        'Open report opens the investigation of the group in a drawer. ' +
        'Investigate starts an investigation of the representative event of the group. ' +
        'Press ? to see the keyboard shortcuts of the list.',
    },
    {
      anchor: 'alerts-same-flow',
      title: 'Same flow chip',
      body:
        'The Same flow chip counts the other detections on the network flow of this row. ' +
        'Click the chip to list them with their verdicts. ' +
        'The chip shows a warning when a true positive and a false positive share the flow.',
    },
  ],
};
// ── END tour: alerts ──

// ── BEGIN tour: investigations ──
export const INVESTIGATIONS_TOUR: Tour = {
  id: 'investigations',
  version: 1,
  name: 'Investigations',
  routes: ['/investigations'],
  steps: [
    {
      anchor: 'investigations-header',
      title: 'Investigations',
      body:
        'This page lists the investigations of soc-ai and their verdicts. ' +
        'The line under the title counts the investigations, the investigations in progress and the true positives in the window.',
    },
    {
      anchor: 'time-filter',
      title: 'Page time filter',
      body:
        'This filter sets the window of the list and of the counts. ' +
        'When the last 24 hours hold no investigation, the list opens on a wider window and says why.',
    },
    {
      anchor: 'investigations-replays',
      title: 'Backtest replays',
      body:
        'The list and its counts leave out the investigations that a backtest ran. ' +
        'Press Show backtest replays to add them. ' +
        'A replay measures the model on an alert that an analyst closed before.',
    },
    {
      anchor: 'investigations-list',
      title: 'Investigation rows',
      body:
        'Each row is one investigation, with its verdict, confidence, flow, status and start time. ' +
        'A chip such as 2 earlier shows the older investigations of the same alert. ' +
        'Click a row to open its report.',
    },
    {
      anchor: 'investigations-select',
      title: 'Row selection',
      body:
        'Select rows with the check boxes to act on them as a group. ' +
        'The toolbar then offers Re-investigate and Delete for the selection. ' +
        'Delete asks first.',
    },
    {
      anchor: 'investigations-waiting-actions',
      title: 'Waiting actions',
      body:
        'The list of waiting actions shows each recommended action on its row. ' +
        'The first button names the write to Security Onion and asks first. ' +
        'Dismiss asks first and offers Undo, for one row or for the selected rows.',
    },
  ],
};
// ── END tour: investigations ──

// ── BEGIN tour: investigation ──
export const INVESTIGATION_TOUR: Tour = {
  id: 'investigation',
  version: 1,
  name: 'Investigation',
  routes: ['/investigation/:id'],
  steps: [
    {
      anchor: 'investigation-header',
      title: 'Investigation report',
      body:
        'This page holds the report of one investigation. ' +
        'The header shows the name and the id of the investigation, its status and its duration.',
    },
    {
      anchor: 'investigation-toolbar',
      title: 'Override and re-run',
      body:
        'Press Override verdict to set your own verdict and an optional reason. ' +
        'Press Re-run investigation to start a new investigation of the alert. ' +
        'A re-run asks first when an analyst verdict stands on the alert.',
    },
    {
      anchor: 'investigation-verdict',
      title: 'Verdict and confidence',
      body:
        'The card shows the verdict, the confidence and the reason for the verdict. ' +
        'The word under the number reads high, medium or low. ' +
        'A number in brackets in the summary opens its timeline step.',
    },
    {
      anchor: 'investigation-evidence',
      title: 'Cited evidence',
      body:
        'These chips name the documents, the alert fields and the tool results that the verdict cites. ' +
        'Click a document id to read the document. ' +
        'A struck-through chip is a citation that the validator did not resolve.',
    },
    {
      anchor: 'investigation-actions',
      title: 'Recommended actions',
      body:
        'This section holds the writes to Security Onion for this alert, such as Escalate to case. ' +
        'Each write asks first and states what one press writes. ' +
        'Dismiss writes nothing to Security Onion and offers Undo.',
    },
    {
      anchor: 'investigation-timeline',
      title: 'Investigation timeline',
      body:
        'The timeline lists each step of the investigation, such as the context gathered, the follow-up queries and the checks. ' +
        'Click a step to show its detail. ' +
        'When the run holds event times, the Event timeline above the steps lists the documents in time order.',
    },
    {
      anchor: 'investigation-context',
      title: 'Alert context',
      body:
        'This column holds the alert details. ' +
        'A Host context panel lists the other alerts on one end of the alert. ' +
        'A Same flow panel names the other detections on the flow of this alert.',
      placement: 'left',
    },
  ],
};
// ── END tour: investigation ──

// ── BEGIN tour: hunts ──
export const HUNTS_TOUR: Tour = {
  id: 'hunts',
  version: 1,
  name: 'Hunts',
  routes: ['/hunts'],
  steps: [
    {
      anchor: 'hunts-header',
      title: 'Hunts',
      body:
        'This page holds the hunting path, from an analytic hit to a lead to a hunt. ' +
        'The line under the title counts the hunts, the findings and the hunts in progress in the page window. ' +
        'The link How this flows opens a chart of the path.',
    },
    {
      anchor: 'hunts-tabs',
      title: 'Page tabs',
      body:
        'The Hunts tab holds the leads, the analytic hits and the hunts. ' +
        'An analytic is one written detection that the sweep runs. ' +
        'Open the Analytics tab to read what each analytic found and to change it.',
    },
    {
      anchor: 'hunts-leads',
      title: 'Leads',
      body:
        'A lead is a set of observations on one entity that waits on one decision. ' +
        'Select leads with the check boxes, then press Dismiss, Hunt or Reopen for the selection. ' +
        'Each press opens a confirm that states the count and the leads it skips.',
    },
    {
      anchor: 'hunts-hits',
      title: 'Analytic hits',
      body:
        'A hit is one match of one analytic on one entity. ' +
        'The block lists the hits of the last 7 days, with the unread shadow hits first. ' +
        'A shadow hit adds no weight to a lead and waits for the analyst to read it.',
    },
    {
      anchor: 'time-filter',
      title: 'Page time filter',
      body:
        'This filter sets the window of the hunt list and of the counts under the title. ' +
        'The leads and the analytic hits state their own scope.',
    },
    {
      anchor: 'grid-gap',
      title: 'Grid gaps',
      body:
        'This strip names each grid gap in the page window. ' +
        GRID_GAP +
        'A closed gap with hits offers a review, where one confirm marks the selected hits benign.',
    },
    {
      anchor: 'hunts-list',
      title: 'Hunt list',
      body:
        'Each row is one hunt in the page window, with its outcome in the Status column. ' +
        'Select the objective of a row to open the hunt. ' +
        'Press New hunt above the list to write a hunt of your own.',
    },
  ],
};
// ── END tour: hunts ──

// ── BEGIN tour: hunt ──
export const HUNT_TOUR: Tour = {
  id: 'hunt',
  version: 1,
  name: 'Hunt',
  routes: ['/hunts/:id'],
  steps: [
    {
      anchor: 'hunt-hero',
      title: 'Hunt outcome',
      body:
        'The badge states the outcome of the hunt. ' +
        'The hunt writes no verdict and takes no action in Security Onion. ' +
        'Press Show objective to read the full objective.',
    },
    {
      anchor: 'hunt-rehunt',
      title: 'Re-hunt',
      body:
        'Re-hunt runs the same objective again as a new hunt. ' +
        'The console then opens the new hunt. ' +
        'When it is complete, the new hunt compares its findings with the last complete run.',
    },
    {
      anchor: 'hunt-lead-decision',
      title: 'Lead decision',
      body:
        'The lead that asked for this hunt waits on a decision. ' +
        'Read each finding and the verdict of its investigation. ' +
        'Press Dismiss lead to close the lead with a reason.',
    },
    {
      anchor: 'hunt-findings',
      title: 'Findings',
      body:
        'When the hunt ends, soc-ai investigates its threat findings up to a cap. ' +
        'The card shows the verdict and links the investigation. ' +
        'Press Open an investigation on a finding that has no investigation.',
    },
    {
      anchor: 'hunt-evidence',
      title: 'Evidence',
      body:
        'The chips under a finding are its evidence. ' +
        'A host chip opens the host page or the entity page. ' +
        'A document chip opens the cited document in a drawer.',
    },
    {
      anchor: 'hunt-event-timeline',
      title: 'Event timeline',
      body:
        'The Event timeline lists the documents that the findings cite, in the order of their event time, in UTC. ' +
        'A new wave starts after a gap of more than 30 minutes between two documents. ' +
        'A chip such as F2 names the finding that cites the document.',
    },
    {
      anchor: 'hunt-timeline',
      title: 'Hunt timeline',
      body:
        'The timeline lists each step of the hunt, with its time. ' +
        'Open a step to read what the model did. ' +
        'A catalog hunt runs one grid query and has no steps.',
    },
  ],
};
// ── END tour: hunt ──

// ── BEGIN tour: lead ──
export const LEAD_TOUR: Tour = {
  id: 'lead',
  version: 1,
  name: 'Lead',
  routes: ['/leads/:id'],
  steps: [
    {
      anchor: 'lead-header',
      title: 'Lead',
      body:
        'A lead is a set of observations that point at one entity. ' +
        'The title names the entity, and the pill shows the state of the lead. ' +
        'Each type chip names one type of observation on the lead.',
    },
    {
      anchor: 'lead-actions',
      title: 'Lead decisions',
      body:
        'Press Hunt this lead to start a hunt on the lead. ' +
        'Press Dismiss to close the lead with a reason. ' +
        'The buttons change with the state, for example Hunt again after a hunt and Reopen on a closed lead.',
    },
    {
      anchor: 'lead-verdict',
      title: 'Lead promotion',
      body:
        'This strip shows when the investigation of a hunt finding reaches a verdict. ' +
        'Press Close the lead to close the lead as Promoted on that investigation. ' +
        'Press Keep open to keep the lead open.',
    },
    {
      anchor: 'lead-weight',
      title: 'Lead weight',
      body:
        'Press Scoring to show the weights of the lead. ' +
        'A lead forms when the observations of two or more types on one entity reach a weight of 0.85. ' +
        'An observation counts half as much after 48 hours.',
    },
    {
      anchor: 'lead-hunts',
      title: 'Hunts on this lead',
      body:
        'Each row is one hunt on this lead, with its outcome. ' +
        'The row states the answer of the hunt and what it could not check. ' +
        'Select a hunt to read its findings and their verdicts.',
    },
    {
      anchor: 'lead-timeline',
      title: 'Observations',
      body:
        'The timeline lists the observations and the decisions on the lead, newest first. ' +
        'Each observation names its type, its analytic and its event window. ' +
        'Select an evidence id to open the document in a drawer.',
    },
  ],
};
// ── END tour: lead ──

// ── BEGIN tour: hosts ──
export const HOSTS_TOUR: Tour = {
  id: 'hosts',
  version: 1,
  name: 'Hosts',
  routes: ['/hosts'],
  steps: [
    {
      anchor: 'hosts-header',
      title: 'Host list',
      body:
        'This page lists the machines that the sweep found on your network. ' +
        'One row is one machine, with every address that soc-ai ties to that machine. ' +
        'Click a row to open the page of the machine.',
    },
    {
      anchor: 'hosts-toolbar',
      title: 'Search and saved views',
      body:
        'The search matches a name, an address, a MAC, the OS, the role or the agent of any machine. ' +
        'Press Save view to keep the current filters as a named view. ' +
        'An admin starts a new sweep with Rebuild now.',
    },
    {
      anchor: 'hosts-summary',
      title: 'Network counts',
      body:
        'The cards and the role bar count every machine that the sweep found. ' +
        'Each count is a link to the machines that it counts. ' +
        'The search and the filters of the list do not change these counts.',
    },
    {
      anchor: 'hosts-conflicts',
      title: 'Disagreements',
      body:
        'This bar counts the declarations that the sweep disagrees with. ' +
        'Press Show to list them. ' +
        'An admin opens a row and settles the disagreement on the host page.',
    },
    {
      anchor: 'hosts-columns',
      title: 'Sort and filter',
      body:
        'Click a column header to sort the list. ' +
        'The filter icons in the Role, Agent, Events and First seen headers narrow the list. ' +
        'Pick all machines in the Events filter to show the machines with no events.',
    },
    {
      anchor: 'hosts-select',
      title: 'Bulk declarations',
      body:
        'Select machines with the check boxes to declare one role or one criticality on all of them. ' +
        'Press Declare to write the value on the primary address of each machine. ' +
        'The result line offers Undo to restore the earlier values.',
    },
    {
      anchor: 'hosts-row',
      title: 'Machine row',
      body:
        'A row shows the name, the primary address, the agent and the role of one machine. ' +
        'The word beside the role says declared, inferred, low confidence or stale. ' +
        'None in the Agent column means that soc-ai sees the machine only in network traffic.',
    },
  ],
};
// ── END tour: hosts ──

// ── BEGIN tour: host ──
export const HOST_TOUR: Tour = {
  id: 'host',
  version: 1,
  name: 'Host',
  routes: ['/hosts/:key'],
  steps: [
    {
      anchor: 'host-hero',
      title: 'Host header',
      body:
        'The header names the machine, its role, its primary address and its agent. ' +
        'The bold lines under the address list the open leads and the verdicts on this machine. ' +
        'The identity sentence states the role, the OS and the domain from the facts.',
    },
    {
      anchor: 'grid-gap',
      title: 'Grid gaps',
      body:
        'This strip names each grid gap in the activity window. ' +
        GRID_GAP +
        'The counts of the window are incomplete.',
    },
    {
      anchor: 'host-briefing',
      title: 'Criticality and warnings',
      body:
        'This strip shows the criticality and the policy note of the machine. ' +
        'It also warns about a disagreement with the sweep and about a missing or late agent. ' +
        "An admin settles a disagreement with Keep mine or Use the sweep's answer.",
    },
    {
      anchor: 'host-work',
      title: 'Investigations, leads and observations',
      body:
        'These panels list the investigations, the leads and the observations that name this machine. ' +
        'A departure from the profile shows here as a profile observation. ' +
        'Open an investigation or a lead to read its evidence.',
    },
    {
      anchor: 'host-activity',
      title: 'Live activity',
      body:
        'These panels show the peers, the connection volume and the users of this machine. ' +
        'soc-ai reads them live from the grid. ' +
        'The 24h and 7d buttons at the top of the page set their window.',
    },
    {
      anchor: 'host-facts',
      title: 'Facts and declarations',
      body:
        'Each row is one fact of the dossier, with its value and its source. ' +
        'A value that an admin declares with Edit replaces the value that the sweep inferred. ' +
        'Open Why? to read the evidence behind a value.',
    },
    {
      anchor: 'host-profile',
      title: 'Behavioural profile',
      body:
        'The profile is the baseline of this host, with one row for each dimension. ' +
        'On a measured row, a new member is a departure. ' +
        'A learning, blind or unmeasurable row scores no departure.',
    },
  ],
};
// ── END tour: host ──

// ── BEGIN tour: entity ──
export const ENTITY_TOUR: Tour = {
  id: 'entity',
  version: 1,
  name: 'Entity',
  routes: ['/entity/:value'],
  steps: [
    {
      anchor: 'entity-header',
      title: 'Entity header',
      body:
        'This page shows an address that no machine holds, a user or a domain. ' +
        'The header states the type of the value. ' +
        'The lines under it count the open leads and the true-positive investigations that name it.',
    },
    {
      anchor: 'entity-seen',
      title: 'Record counts',
      body:
        'This line gives the time of the first and the last soc-ai record of the value. ' +
        'It counts the investigations, the hunt findings and the leads that name it, and the observations of the last 30 days.',
    },
    {
      anchor: 'entity-hunting',
      title: 'Leads and observations',
      body:
        'The leads panel lists the leads that name the value. ' +
        'The observations panel lists the observations of the last 7 days from every source. ' +
        'Open a lead to read its evidence.',
    },
    {
      anchor: 'entity-timeline',
      title: 'Investigations and hunt findings',
      body:
        'This list holds the investigations and the hunt findings that name the value, newest first. ' +
        'An investigation shows its verdict, and a hunt finding shows its severity. ' +
        'Open a card to read the investigation or the hunt.',
    },
  ],
};
// ── END tour: entity ──

// ── BEGIN tour: settings ──
export const SETTINGS_TOUR: Tour = {
  id: 'settings',
  version: 1,
  name: 'Settings',
  routes: ['/config'],
  steps: [
    {
      anchor: 'settings-header',
      title: 'Settings',
      body:
        'Settings holds the runtime configuration of soc-ai. ' +
        'Only an admin can open this page. ' +
        'The line under the title explains the origin badges DEFAULT, ENV and DB.',
    },
    {
      anchor: 'settings-search',
      title: 'Settings search',
      body:
        'Type a label, a key or a word of the help text to find a setting. ' +
        'Click a result to open its section and mark the setting. ' +
        'Press Escape to clear the search.',
      placement: 'right',
    },
    {
      anchor: 'settings-sections',
      title: 'Section list',
      body:
        'The list groups the sections under headings such as Models & Reasoning and System. ' +
        'Select a section to show it in the pane on the right. ' +
        'Users and API tokens are under System.',
      placement: 'right',
    },
    {
      anchor: 'settings-section',
      title: 'Day-1 settings',
      body:
        'A section shows its day-1 settings first. ' +
        'The Advanced fold holds the other settings of the section. ' +
        'Settings search also finds a setting behind the fold.',
    },
    {
      anchor: 'settings-row',
      title: 'Setting changes',
      body:
        'An edit stays unsaved until you press Apply changes. ' +
        'A HOT-APPLY setting then takes effect at once. ' +
        'A RESTART setting takes effect at the next start of soc-ai.',
    },
  ],
};
// ── END tour: settings ──

// ── BEGIN tour: status ──
export const STATUS_TOUR: Tour = {
  id: 'status',
  version: 1,
  name: 'Status',
  routes: ['/operate'],
  steps: [
    {
      anchor: 'status-header',
      title: 'Status',
      body:
        'This page shows the state of the work that soc-ai runs with no operator. ' +
        'The cards at the end of the page open Settings, Backtest and Runbooks.',
    },
    {
      anchor: 'status-dependencies',
      title: 'Dependencies',
      body:
        'This panel shows Security Onion, Elasticsearch and the model gateway. ' +
        'Each row reads up, slow, down or unknown, with the reason. ' +
        'Connection settings opens the connection in Settings.',
    },
    {
      anchor: 'status-jobs',
      title: 'Scheduled jobs',
      body:
        'Each row shows a job that runs with no operator, such as the dossier sweep or the nightly backup. ' +
        'The row shows the state, the last run and the last result. ' +
        'Setting opens the setting of the job.',
    },
    {
      anchor: 'status-sweep',
      title: 'Analytic sweep',
      body:
        'This line states if the analytic sweep is on, how often it runs and when it last ran. ' +
        'Each row below shows one analytic and its counts. ' +
        'Select the title of a row to read the analytic.',
    },
    {
      anchor: 'status-escalations',
      title: 'Escalations awaiting an answer',
      body:
        'This panel lists each escalation that has no case from Security Onion yet. ' +
        'Press Check Security Onion now on a row to look for the case in Security Onion. ' +
        'The check writes nothing to Security Onion.',
    },
  ],
};
// ── END tour: status ──

// ── BEGIN tour: backtest ──
export const BACKTEST_TOUR: Tour = {
  id: 'backtest',
  version: 1,
  name: 'Backtest',
  routes: ['/backtest'],
  steps: [
    {
      anchor: 'backtest-header',
      title: 'Backtest',
      body:
        'This page measures soc-ai on alerts that the analysts already closed in Security Onion. ' +
        'soc-ai replays its triage on a sample and compares each verdict with the decision of the analyst. ' +
        'A backtest writes nothing to Security Onion.',
    },
    {
      anchor: 'backtest-form',
      title: 'New backtest',
      body:
        'Choose the window, the sample size and the minimum severity. ' +
        'Run backtest shows the cost of the run before Start backtest starts it. ' +
        'Only an admin can start a backtest.',
    },
    {
      anchor: 'backtest-cancel',
      title: 'Cancel backtest',
      body:
        'Cancel backtest asks first and then stops the run after the current alert. ' +
        'soc-ai keeps the results of the alerts that finished. ' +
        'Only an admin can cancel a backtest.',
    },
    {
      anchor: 'backtest-runs',
      title: 'Past runs',
      body:
        'This list shows the stored backtests, newest first. ' +
        'Press Open to read the report of an earlier run.',
    },
    {
      anchor: 'backtest-figures',
      title: 'Report figures',
      body:
        'Agreement with analysts is the share of replayed verdicts that match the decision of the analyst. ' +
        'An escalated alert counts as a true positive, and an acknowledged alert counts as a false positive. ' +
        'Missed true positives counts the escalated alerts that soc-ai called a false positive.',
    },
    {
      anchor: 'backtest-table',
      title: 'Per-alert comparison',
      body:
        'Each row compares the verdict of soc-ai with the decision of the analyst for one alert. ' +
        'Click the rule name to open the replay investigation.',
    },
  ],
};
// ── END tour: backtest ──

// ── BEGIN tour: runbooks ──
export const RUNBOOKS_TOUR: Tour = {
  id: 'runbooks',
  version: 1,
  name: 'Runbooks',
  routes: ['/runbooks'],
  steps: [
    {
      anchor: 'runbooks-header',
      title: 'Runbooks',
      body:
        'A runbook holds the triage guidance of your team. ' +
        'The model searches the runbooks during an investigation and cites the best match. ' +
        'Only an admin can add, change or delete a runbook.',
    },
    {
      anchor: 'runbooks-toolbar',
      title: 'Add runbooks',
      body:
        'Import files adds runbooks from your markdown files. ' +
        'Load starter pack adds 10 generic runbooks and skips each title that you already have. ' +
        'New runbook opens an empty editor.',
    },
    {
      anchor: 'runbooks-draft',
      title: 'Draft from history',
      body:
        'Draft from history lists each rule with 3 or more completed investigations and no runbook. ' +
        'The model writes a draft for the rule that you pick. ' +
        'The model does not cite a draft until you approve it.',
    },
    {
      anchor: 'runbooks-search',
      title: 'Runbook search',
      body:
        'Type words to filter the list. ' +
        'Each word must match the title, a tag, a linked rule or the content of a runbook.',
    },
    {
      anchor: 'runbooks-list',
      title: 'Runbook list',
      body:
        'Select a row to open the runbook in the editor. ' +
        'A linked rule chip opens the alerts of that rule for the last 30 days. ' +
        'Delete asks first.',
    },
    {
      anchor: 'runbooks-editor',
      title: 'Runbook editor',
      body:
        'The editor holds the title, the markdown content, the tags and the linked rules. ' +
        'A linked rule is the name or the UUID of a detection rule. ' +
        'The runbook ranks first when a linked rule fires.',
    },
  ],
};
// ── END tour: runbooks ──

// ── BEGIN tour: notifications ──
export const NOTIFICATIONS_TOUR: Tour = {
  id: 'notifications',
  version: 1,
  name: 'Notifications',
  routes: ['/notifications'],
  steps: [
    {
      anchor: 'notifications-header',
      title: 'Notifications',
      body:
        'This page lists the notifications of the console, such as a finished hunt or a finished investigation. ' +
        'The line under the title counts the notifications on the list.',
    },
    {
      anchor: 'notifications-dismiss-all',
      title: 'Dismiss all',
      body:
        'Dismiss all hides every notification up to now and marks every unread shadow hit read. ' +
        'It asks first. ' +
        'Leads and the other decisions stay.',
    },
    {
      anchor: 'notifications-needs-you',
      title: 'Needs you',
      body:
        'This block lists each part of the count on the bell badge. ' +
        'Each line states its scope and opens the list that holds the work.',
    },
    {
      anchor: 'notifications-filters',
      title: 'Types and urgency',
      body:
        'Press a type chip to show one type of notification. ' +
        'Urgency filters the rows by the color of the dot. ' +
        'Urgent is red, Attention is amber and Informational is blue.',
    },
    {
      anchor: 'notifications-list',
      title: 'Notification list',
      body:
        'Each row is one notification. ' +
        'A linked title opens the record that the notification names. ' +
        'The X at the end of a row takes the notification off the list.',
    },
  ],
};
// ── END tour: notifications ──

export const PAGE_TOURS: readonly Tour[] = [
  DASHBOARD_TOUR,
  ALERTS_TOUR,
  INVESTIGATIONS_TOUR,
  INVESTIGATION_TOUR,
  HUNTS_TOUR,
  HUNT_TOUR,
  LEAD_TOUR,
  HOSTS_TOUR,
  HOST_TOUR,
  ENTITY_TOUR,
  SETTINGS_TOUR,
  STATUS_TOUR,
  BACKTEST_TOUR,
  RUNBOOKS_TOUR,
  NOTIFICATIONS_TOUR,
];

export const ALL_TOURS: readonly Tour[] = [WELCOME_TOUR, ...PAGE_TOURS];

/** A tour by its id, or undefined. */
export function tourById(id: string): Tour | undefined {
  return ALL_TOURS.find((t) => t.id === id);
}

/** The page tour of a path, or undefined when the page has none. A tour with
 *  no steps yet counts as none. */
export function pageTourFor(pathname: string): Tour | undefined {
  return PAGE_TOURS.find(
    (t) => t.steps.length > 0 && t.routes.some((r) => matchPath({ path: r, end: true }, pathname)),
  );
}
