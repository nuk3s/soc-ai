// The chat footer, cited ids in answers, the live region, and the drawer's
// name and focus return (fleet dogfood 2026-10-01: P3, P11, P13).
import { fireEvent, render, screen } from '@testing-library/react';
import { useRef, useState } from 'react';
import { describe, expect, it } from 'vitest';
import { ShellProvider } from '../shell/ShellContext';
import { AssistantBubble, ChatPanelShell, toolsSummary } from './ChatDock';
import { Drawer } from './Drawer';

describe('the tools footer (P11)', () => {
  it('counts calls by tool in words', () => {
    const tools = Array(14).fill('t_query_events_oql').concat(['t_enrich_ip']).join(', ');
    expect(toolsSummary(tools)).toBe('Tools used: 14 event queries, 1 IP lookup');
  });

  it('renders no raw identifier', () => {
    const { container } = render(<AssistantBubble text="Done." tools="t_query_events_oql, t_query_events_oql" />);
    expect(container.textContent).toContain('Tools used: 2 event queries');
    expect(container.textContent).not.toContain('t_query_events_oql');
  });

  it('says nothing for no tools', () => {
    expect(toolsSummary('')).toBeNull();
    expect(toolsSummary(null)).toBeNull();
  });
});

describe('ids in an answer (P3)', () => {
  const ID = 'UbhH2KABxYz0123456_q';

  it('lists a cited id as a control when the scope links ids', () => {
    render(<AssistantBubble text={`The flow is in ${ID}.`} linkIds={[]} />);
    expect(screen.getByRole('button', { name: ID })).toBeTruthy();
  });

  it('links nothing when the caller did not ask', () => {
    // Negative control: the Dashboard chat passes no linkIds.
    render(<AssistantBubble text={`The flow is in ${ID}.`} />);
    expect(screen.queryByRole('button', { name: ID })).toBeNull();
  });
});

describe('the message list (P13)', () => {
  it('is a polite live region', () => {
    render(
      <ChatPanelShell
        title="Chat about this investigation"
        scopeLabel="scope"
        placeholder="Ask"
        messages={[{ role: 'assistant', text: 'An answer.' }]}
        pending={false}
        draft=""
        onDraft={() => {}}
        onSend={() => {}}
        listSizeClass=""
      />,
    );
    const log = screen.getByRole('log');
    expect(log).toHaveAttribute('aria-live', 'polite');
    expect(log).toHaveTextContent('An answer.');
  });
});

function DrawerHarness() {
  const rowRef = useRef<HTMLDivElement>(null);
  const [open, setOpen] = useState(false);
  return (
    <ShellProvider>
      <div ref={rowRef} tabIndex={-1} data-testid="row" onClick={() => setOpen(true)}>
        row
      </div>
      <Drawer
        open={open}
        onClose={() => setOpen(false)}
        ariaLabel="ET SCAN Potential SSH Scan"
        returnFocusRef={rowRef}
        header={
          <>
            <span>ET SCAN Potential SSH Scan</span>
            <button type="button">Permalink</button>
          </>
        }
      >
        body
      </Drawer>
    </ShellProvider>
  );
}

describe('the investigation drawer (P13)', () => {
  it('takes its name from the investigation, not the header buttons', () => {
    render(<DrawerHarness />);
    fireEvent.click(screen.getByTestId('row'));
    expect(screen.getByRole('dialog')).toHaveAccessibleName('ET SCAN Potential SSH Scan');
  });

  it('hands focus back to the row on Escape', () => {
    render(<DrawerHarness />);
    // A click on a row body leaves focus on BODY: the case the opener misses.
    fireEvent.click(screen.getByTestId('row'));
    expect(document.activeElement).not.toBe(screen.getByTestId('row'));
    fireEvent.keyDown(document, { key: 'Escape' });
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(document.activeElement).toBe(screen.getByTestId('row'));
  });
});
