// Two dogfood fixes on the Runbooks list rows:
//  (4) the whole title/body area opens the runbook (it used to open only via
//      the trailing "Edit" button — the title/body was a dead <span>).
//  (5) the list preview stripped the leading `# Title` heading so the row no
//      longer repeats its own title verbatim on the line beneath it.
import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';

const RUNBOOK = vi.hoisted(() => ({
  id: 42,
  title: 'Beaconing Triage',
  // Body opens with a `# Beaconing Triage` heading that matches the title —
  // the exact shape that produced the duplicated preview.
  content: '# Beaconing Triage\n\nCheck the JA3 hash against the known-good baseline.',
  tags: [],
  linked_rules: [],
  draft: false,
  created_by: 'analyst',
  created_at: '2026-07-14T10:00:00Z',
  updated_at: '2026-07-14T10:00:00Z',
  embedded: null,
  stale: null,
}));

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getRunbooks: vi.fn().mockResolvedValue([RUNBOOK]),
}));

import { Runbooks } from './Runbooks';

describe('Runbooks list rows', () => {
  it('opens the editor when the card title/body is clicked (not just Edit)', async () => {
    render(<Runbooks />);
    // Click the row title itself — the click must bubble to the card button and
    // open the editor with this runbook loaded.
    fireEvent.click(await screen.findByText('Beaconing Triage'));
    const titleInput = (await screen.findByPlaceholderText(
      'e.g. Triage an ET SCAN Nmap alert',
    )) as HTMLInputElement;
    expect(titleInput.value).toBe('Beaconing Triage');
  });

  it('strips the leading title from the row preview so it is not duplicated', async () => {
    render(<Runbooks />);
    const preview = await screen.findByText(/Check the JA3 hash/);
    // Before the fix the preview read "Beaconing Triage Check the JA3 …".
    expect(preview.textContent).not.toMatch(/Beaconing Triage/);
  });
});
