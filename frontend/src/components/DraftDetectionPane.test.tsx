// The draft-detection review pane's own honesty rules (dogfood 1.3):
//  - the reassurance explainer ("nothing is written to Security Onion") shows
//    on BOTH surfaces, including the Hunt Console's one-click autoRun mount
//    where the draft fires with no other context (F20);
//  - the validator's verdict and the dry run describe the ORIGINAL draft, so
//    the moment the analyst edits the YAML the pane must stop asserting
//    validity of text nobody checked (F4);
//  - the green badge says "Rule structure valid", not "Schema valid" — the
//    check is parse + required keys + recognized fields, not proof Security
//    Onion will load the rule, and the would-have-fired count is measured by
//    the rule's OQL twin (F6).
import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import type { SigmaDraft } from '../lib/types';
import { DraftDetectionPane } from './DraftDetectionPane';

const ORIGINAL_YAML =
  'title: DC01 dce_rpc burst\nlogsource:\n  category: dce_rpc\ndetection:\n  selection:\n    dce_rpc.operation: NetrServerAuthenticate3\n  condition: selection\n';

const sigmaDraft = (over: Partial<SigmaDraft> = {}): SigmaDraft => ({
  title: 'DC01 dce_rpc NetrServerAuthenticate3 burst',
  sigma_yaml: ORIGINAL_YAML,
  oql: 'event.dataset:zeek.dce_rpc AND zeek.dce_rpc.operation:NetrServerAuthenticate3',
  rationale: "Fires on the same Netlogon operation sequence the finding's evidence cited.",
  validator_note: null,
  schema_ok: true,
  dry_run: {
    ran: true,
    hit_count: 4,
    total_is_lower_bound: false,
    sample_ids: ['tel-doc-000001'],
    window_days: 30,
    error: null,
  },
  ...over,
});

const EXPLAINER = /nothing is written to security onion/i;
const STALE_NOTICE = /your edits have not been re-checked/i;

describe('DraftDetectionPane — autoRun explainer (F20)', () => {
  it('shows the explainer and a loading state while the one-click draft runs, and keeps the explainer above the result', async () => {
    let resolveDraft!: (d: SigmaDraft) => void;
    const onDraft = () => new Promise<SigmaDraft>((res) => (resolveDraft = res));
    render(<DraftDetectionPane autoRun onDraft={onDraft} />);

    // While the draft is in flight (16–44s live): the reassurance copy and a
    // visible wait state, not a bare empty panel.
    expect(screen.getByText(EXPLAINER)).toBeTruthy();
    expect(screen.getByText(/drafting a detection/i)).toBeTruthy();
    // But no second trigger — the autoRun caller owns the button.
    expect(screen.queryByRole('button', { name: /draft detection/i })).toBeNull();

    resolveDraft(sigmaDraft());
    expect(await screen.findByText('DC01 dce_rpc NetrServerAuthenticate3 burst')).toBeTruthy();
    // The explainer stays with the result, matching the investigation surface.
    expect(screen.getByText(EXPLAINER)).toBeTruthy();
  });
});

describe('DraftDetectionPane — stale-edit honesty (F4) + structure label (F6)', () => {
  it('relabels the badge, cites the OQL twin for the dry-run count, and withdraws both once the YAML is edited', async () => {
    render(<DraftDetectionPane autoRun onDraft={() => Promise.resolve(sigmaDraft())} />);

    // Fresh draft: the structure badge (not "Schema valid") and the dry run,
    // with the one-line note attributing the count to the rule's OQL twin.
    expect(await screen.findByText('Rule structure valid')).toBeTruthy();
    expect(screen.queryByText('Schema valid')).toBeNull();
    expect(screen.getByText(/would have fired 4×/i)).toBeTruthy();
    expect(screen.getByText(/oql twin/i)).toBeTruthy();
    expect(screen.queryByText(STALE_NOTICE)).toBeNull();

    // Edit the textarea → the badge no longer vouches for text nobody checked.
    const textarea = screen.getByLabelText(/sigma rule \(yaml\)/i) as HTMLTextAreaElement;
    fireEvent.change(textarea, { target: { value: 'title: EDITED BY ANALYST\n' } });

    expect(screen.getByText(STALE_NOTICE)).toBeTruthy();
    expect(screen.queryByText('Rule structure valid')).toBeNull();

    // Reverting to the exact original restores the verdict — staleness is a
    // live comparison, not a one-way latch.
    fireEvent.change(textarea, { target: { value: ORIGINAL_YAML } });
    expect(screen.getByText('Rule structure valid')).toBeTruthy();
    expect(screen.queryByText(STALE_NOTICE)).toBeNull();
  });

  it('also withdraws a FAILED structure verdict on edit — the failure described the original too', async () => {
    render(
      <DraftDetectionPane
        autoRun
        onDraft={() =>
          Promise.resolve(
            sigmaDraft({
              schema_ok: false,
              validator_note: 'Sigma rule missing required keys (title/logsource/detection).',
            }),
          )
        }
      />,
    );

    expect(
      await screen.findByText('Sigma rule missing required keys (title/logsource/detection).'),
    ).toBeTruthy();

    const textarea = screen.getByLabelText(/sigma rule \(yaml\)/i) as HTMLTextAreaElement;
    fireEvent.change(textarea, { target: { value: 'title: now fixed by hand\n' } });

    expect(screen.getByText(STALE_NOTICE)).toBeTruthy();
    expect(
      screen.queryByText('Sigma rule missing required keys (title/logsource/detection).'),
    ).toBeNull();
  });
});
