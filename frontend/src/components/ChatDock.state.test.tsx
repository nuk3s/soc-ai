// The chat thread: entity links in answers (R1-D5), the step names of the
// progress line (R1-D23) and a send that cannot work (H1-D13).
import { fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import { AssistantBubble, ChatThreadView, toolLabel, toolsSummary } from './ChatDock';

describe('entity links in an answer', () => {
  it('opens an address, a lead and an investigation in the console', async () => {
    const ULID = `01J${'B'.repeat(23)}`;
    render(
      <MemoryRouter>
        <AssistantBubble text={`192.0.2.40 is in Lead 11 and ${ULID}.`} linkEntities />
      </MemoryRouter>,
    );
    const ip = await screen.findByRole('link', { name: '192.0.2.40' });
    expect(ip).toHaveAttribute('href', '/entity/192.0.2.40');
    // An in-app link: no new tab.
    expect(ip).not.toHaveAttribute('target');
    expect(screen.getByRole('link', { name: 'Lead 11' })).toHaveAttribute('href', '/leads/11');
    expect(screen.getByRole('link', { name: ULID })).toHaveAttribute('href', `/investigation/${ULID}`);
  });

  it('links nothing when the caller did not ask', async () => {
    render(
      <MemoryRouter>
        <AssistantBubble text="192.0.2.40 is quiet. Done." />
      </MemoryRouter>,
    );
    await screen.findByText(/is quiet/);
    expect(screen.queryByRole('link')).toBeNull();
  });

  it('keeps an outside link in a new tab', async () => {
    render(
      <MemoryRouter>
        <AssistantBubble text="Read [the advisory](https://example.com/a)." linkEntities />
      </MemoryRouter>,
    );
    const a = await screen.findByRole('link', { name: 'the advisory' });
    expect(a).toHaveAttribute('target', '_blank');
  });
});

describe('the progress step names', () => {
  it('names each tool as a step', () => {
    expect(toolLabel('t_host_dossier')).toBe('Reading the dossier');
    expect(toolLabel('t_field_values')).toBe('Reading field values');
    expect(toolLabel('partial_answer')).toBe('Writing an answer from the results so far');
    // A tool this map does not hold still reads as a step.
    expect(toolLabel('t_new_probe')).toBe('Running new probe');
  });

  it('counts the new tools in words', () => {
    expect(toolsSummary('t_field_values, t_field_values, t_host_dossier')).toBe(
      'Tools used: 2 field value reads, 1 dossier read',
    );
  });
});

describe('a send that cannot work', () => {
  const view = (props: { blockedReason?: string | null; stateNote?: string | null }) => {
    const onSend = vi.fn();
    render(
      <ChatThreadView
        label="Ask soc-ai, general"
        placeholder="Ask"
        messages={[]}
        pending={false}
        draft="What datasets do I have?"
        onDraft={() => {}}
        onSend={onSend}
        {...props}
      />,
    );
    return onSend;
  };

  it('turns the send off and says why', () => {
    const onSend = view({ blockedReason: 'The model gateway does not answer.' });
    expect(screen.getByRole('status')).toHaveTextContent('The model gateway does not answer.');
    const send = screen.getByLabelText('Send');
    expect(send).toBeDisabled();
    fireEvent.keyDown(screen.getByLabelText('Your question'), { key: 'Enter' });
    expect(onSend).not.toHaveBeenCalled();
  });

  it('keeps the send with a note', () => {
    const onSend = view({ stateNote: 'The grid does not answer.' });
    expect(screen.getByRole('status')).toHaveTextContent('The grid does not answer.');
    fireEvent.click(screen.getByLabelText('Send'));
    expect(onSend).toHaveBeenCalledTimes(1);
  });

  it('shows no state line when all is well', () => {
    view({});
    expect(screen.queryByTestId('chat-state')).toBeNull();
  });
});
