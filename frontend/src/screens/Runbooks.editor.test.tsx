// Dogfood 2026-10-19 on the Runbooks screen.
//
// R5-D16: the "linked rule" chip looked like a link and did nothing.
// R5-D23: the editor labels named no control, so a screen reader read four
// unnamed fields. R5-D24: the delete confirm ignored Escape and did not say
// what a delete does. R5-I11: Create closed the editor on the new runbook.
// R5-41: the linked-rules hint read "This is the strongest match signal."
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const RUNBOOK = vi.hoisted(() => ({
  id: 7,
  title: 'Triage an ET SCAN Nmap alert',
  content: 'Steps to triage.',
  tags: ['scan'],
  linked_rules: ['ET SCAN Nmap'],
  draft: false,
  created_by: 'analyst',
  created_at: '2026-07-01T00:00:00+00:00',
  updated_at: '2026-07-20T00:00:00+00:00',
  embedded: null,
  stale: null,
}));

const createRunbookMock = vi.hoisted(() => vi.fn());
const deleteRunbookMock = vi.hoisted(() => vi.fn());
const getRunbooksMock = vi.hoisted(() => vi.fn());

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getRunbooks: getRunbooksMock,
  createRunbook: createRunbookMock,
  deleteRunbook: deleteRunbookMock,
}));

import { Runbooks } from './Runbooks';

const mount = async () => {
  render(
    <MemoryRouter>
      <Runbooks />
    </MemoryRouter>,
  );
  await screen.findByText('Triage an ET SCAN Nmap alert');
};

beforeEach(() => {
  getRunbooksMock.mockReset();
  getRunbooksMock.mockResolvedValue([RUNBOOK]);
  createRunbookMock.mockReset();
  deleteRunbookMock.mockReset();
  deleteRunbookMock.mockResolvedValue({ deleted: true });
});

describe('the editor', () => {
  it('ties every label to its control', async () => {
    await mount();
    fireEvent.click(screen.getAllByRole('button', { name: /New runbook/ })[0]);
    expect((await screen.findByLabelText('Title')).tagName).toBe('INPUT');
    expect(screen.getByLabelText('Markdown content').tagName).toBe('TEXTAREA');
    expect(screen.getByLabelText('Tags').tagName).toBe('INPUT');
    expect(screen.getByLabelText('Linked rules').tagName).toBe('INPUT');
  });

  it('says what a linked rule does in the words of the model', async () => {
    await mount();
    fireEvent.click(screen.getAllByRole('button', { name: /New runbook/ })[0]);
    expect(
      await screen.findByPlaceholderText('Rule names or UUIDs. A linked rule ranks the runbook first.'),
    ).toBeTruthy();
    expect(screen.getByPlaceholderText(/^The procedure the model cites\./)).toBeTruthy();
  });

  it('keeps a new runbook open after Create', async () => {
    const created = { ...RUNBOOK, id: 9, title: 'Triage a DNS tunnel', content: 'Look at the TXT records.', tags: [], linked_rules: [] };
    createRunbookMock.mockResolvedValue(created);
    await mount();
    fireEvent.click(screen.getAllByRole('button', { name: /New runbook/ })[0]);
    fireEvent.change(await screen.findByLabelText('Title'), {
      target: { value: 'Triage a DNS tunnel' },
    });
    fireEvent.change(screen.getByLabelText('Markdown content'), {
      target: { value: 'Look at the TXT records.' },
    });
    getRunbooksMock.mockResolvedValue([RUNBOOK, created]);
    fireEvent.click(screen.getByRole('button', { name: 'Create runbook' }));

    await waitFor(() => expect(createRunbookMock).toHaveBeenCalledTimes(1));
    // The editor stays on the new runbook, which now saves as an edit.
    expect(await screen.findByRole('button', { name: 'Save changes' })).toBeTruthy();
    expect((screen.getByLabelText('Title') as HTMLInputElement).value).toBe('Triage a DNS tunnel');
    // The list reload shows its own loading status, so read the note by text.
    const note = await screen.findByText('soc-ai created the runbook.');
    expect(note.getAttribute('role')).toBe('status');
  });
});

describe('the linked rule chip', () => {
  it('links to the alerts of the rule, outside the row button', async () => {
    await mount();
    const link = screen.getByRole('link', { name: /ET SCAN Nmap/ });
    expect(link.getAttribute('href')).toBe(
      `/alerts?range=30d&hide_acked=false&q=${encodeURIComponent('rule.name:"ET SCAN Nmap"')}`,
    );
    // A link inside the row button is invalid markup, and a click opened the
    // editor instead.
    expect(link.closest('button')).toBeNull();
  });

  it('reads a rule UUID as a rule UUID', async () => {
    getRunbooksMock.mockResolvedValue([
      { ...RUNBOOK, linked_rules: ['8a1b6f8e-2c4d-4e1f-9a7b-3c2d1e0f9a8b', '2001219'] },
    ]);
    await mount();
    const links = screen.getAllByRole('link');
    expect(links.map((a) => decodeURIComponent(a.getAttribute('href') ?? ''))).toEqual([
      '/alerts?range=30d&hide_acked=false&q=rule.uuid:"8a1b6f8e-2c4d-4e1f-9a7b-3c2d1e0f9a8b"',
      '/alerts?range=30d&hide_acked=false&q=rule.uuid:"2001219"',
    ]);
  });
});

describe('the delete confirm', () => {
  it('states what a delete does, and Escape cancels it', async () => {
    await mount();
    fireEvent.click(screen.getByRole('button', { name: 'Delete' }));
    const confirm = await screen.findByTestId('runbook-delete-confirm-7');
    expect(confirm).toHaveTextContent(
      'Select Confirm delete to remove the runbook “Triage an ET SCAN Nmap alert”. The model then stops citing it. You cannot undo this.',
    );
    // The safe button holds the focus, so Escape and Enter both cancel.
    expect(document.activeElement).toBe(screen.getByRole('button', { name: 'Cancel' }));

    act(() => {
      fireEvent.keyDown(document.activeElement ?? document.body, { key: 'Escape' });
    });
    expect(screen.queryByTestId('runbook-delete-confirm-7')).toBeNull();
    expect(screen.getByRole('button', { name: 'Delete' })).toBeTruthy();
    expect(deleteRunbookMock).not.toHaveBeenCalled();
  });

  it('still deletes on Confirm delete', async () => {
    await mount();
    fireEvent.click(screen.getByRole('button', { name: 'Delete' }));
    const confirm = await screen.findByTestId('runbook-delete-confirm-7');
    fireEvent.click(within(confirm.parentElement as HTMLElement).getByRole('button', { name: 'Confirm delete' }));
    await waitFor(() => expect(deleteRunbookMock).toHaveBeenCalledWith(7));
  });
});
