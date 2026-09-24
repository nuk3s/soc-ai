// An evidence id is the proof an analytic works. Until this drawer existed
// the id was a dashed chip beside a comment saying the app had no document
// viewer, so the one thing that settles "did this analytic match the right
// thing" was unreadable. These tests pin the two states that decide that: a
// chip opens the document, and an id the grid no longer holds says so.
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getEvent: vi.fn(),
}));

import { ApiError, getEvent, type EventDocument } from '../lib/api';
import { ShellProvider } from '../shell/ShellContext';
import { DocumentChip, DocumentDrawer } from './DocumentDrawer';

const DOC: EventDocument = {
  id: '7Kq2c1',
  dataset: 'windows.security',
  timestamp: '2026-09-18T10:00:00Z',
  source: {
    winlog: { event_id: 4769, computer_name: 'WS-14' },
    user: { name: 'svc_sql' },
    tags: ['kerberos', 'service_account'],
    message: 'A Kerberos service ticket was requested.',
  },
};

beforeEach(() => {
  vi.mocked(getEvent).mockReset().mockResolvedValue(DOC);
});

// A drawer for a thing that also has a page carries "Open page" in its
// header. A document has no page, so this drawer carries none.
describe('DocumentDrawer header', () => {
  it('carries no Open page, because a document has no page', async () => {
    render(
      <ShellProvider>
        <DocumentDrawer documentId="7Kq2c1" onClose={() => {}} />
      </ShellProvider>,
    );
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByTestId('document-id').textContent).toBe('7Kq2c1');
    expect(within(dialog).queryByText(/open page/i)).toBeNull();
  });
});

describe('DocumentChip', () => {
  it('opens the drawer on the id and shows a flattened key', async () => {
    render(
      <ShellProvider>
        <DocumentChip id="7Kq2c1" />
      </ShellProvider>,
    );
    fireEvent.click(screen.getByRole('button', { name: '7Kq2c1' }));
    await waitFor(() => expect(getEvent).toHaveBeenCalledWith('7Kq2c1'));
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText('winlog.event_id')).toBeTruthy();
    expect(within(dialog).getByText('4769')).toBeTruthy();
    expect(within(dialog).getByText('windows.security')).toBeTruthy();
  });

  it('reads no document before the analyst opens one', () => {
    render(
      <ShellProvider>
        <DocumentChip id="7Kq2c1" />
      </ShellProvider>,
    );
    expect(getEvent).not.toHaveBeenCalled();
    expect(screen.queryByRole('dialog')).toBeNull();
  });
});

describe('DocumentDrawer', () => {
  const mount = (id: string | null = '7Kq2c1') =>
    render(
      <ShellProvider>
        <DocumentDrawer documentId={id} onClose={() => {}} />
      </ShellProvider>,
    );

  it('sorts the keys and joins an array into one value', async () => {
    mount();
    const dialog = await screen.findByRole('dialog');
    const keys = within(dialog)
      .getAllByTestId('document-key')
      .map((k) => k.textContent);
    expect(keys).toEqual([
      'message',
      'tags',
      'user.name',
      'winlog.computer_name',
      'winlog.event_id',
    ]);
    expect(within(dialog).getByText('kerberos, service_account')).toBeTruthy();
  });

  it('says the grid holds no document with this id', async () => {
    vi.mocked(getEvent).mockRejectedValue(
      new ApiError('no document', 404, 'event_not_found'),
    );
    mount();
    await waitFor(() =>
      expect(
        screen.getByText('The grid holds no document with this id. It may have aged out.'),
      ).toBeTruthy(),
    );
  });

  it('states a read that failed for another reason', async () => {
    vi.mocked(getEvent).mockRejectedValue(new ApiError('boom', 503));
    mount();
    await waitFor(() => expect(screen.getByText('Could not read the document.')).toBeTruthy());
  });

  it('copies the document as JSON', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
    mount();
    const dialog = await screen.findByRole('dialog');
    fireEvent.click(within(dialog).getByRole('button', { name: 'Copy JSON' }));
    await waitFor(() => expect(writeText).toHaveBeenCalled());
    expect(JSON.parse(writeText.mock.calls[0][0])).toEqual(DOC.source);
  });

  it('reads nothing while no document is named', () => {
    mount(null);
    expect(getEvent).not.toHaveBeenCalled();
    expect(screen.queryByRole('dialog')).toBeNull();
  });
});


// A finding that cites nothing opened the drawer on an empty id. The drawer
// asked the grid for /events/ and blamed the grid for the 404.
describe('DocumentDrawer with no id', () => {
  it('says no id was given, and reads nothing', async () => {
    render(
      <ShellProvider>
        <DocumentDrawer documentId="" onClose={() => {}} />
      </ShellProvider>,
    );
    expect(await screen.findByText('No document id was given.')).toBeTruthy();
    expect(getEvent).not.toHaveBeenCalled();
    expect(screen.queryByText(/The grid holds no document/)).toBeNull();
  });
});
