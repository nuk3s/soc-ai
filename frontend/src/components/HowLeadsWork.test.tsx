// Dogfood 2026-11-17, N8: three grey paragraphs of lead policy stood above
// the facts of the Hunts page, the lead page and the host page. They sit
// behind one closed disclosure "How leads work" on each page.
import { fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';
import { LEADS_NOTE_AUTO_HUNT, LEAD_LEGEND, LEGEND_AUTO_HUNT } from '../lib/tooltips';
import { HOW_LEADS_WORK, HowLeadsWork, LEADS_NOTE_MANUAL } from './HowLeadsWork';

const mount = (autoHunt: boolean) =>
  render(
    <MemoryRouter>
      <HowLeadsWork autoHunt={autoHunt} />
    </MemoryRouter>,
  );

describe('HowLeadsWork', () => {
  it('holds the definition, the legend and the note behind one closed disclosure', async () => {
    mount(true);
    const how = await screen.findByTestId('how-leads-work');
    expect(how.tagName).toBe('DETAILS');
    expect(how.hasAttribute('open')).toBe(false);
    expect(screen.getByText(HOW_LEADS_WORK).tagName).toBe('SUMMARY');
    expect(how).toContainElement(screen.getByTestId('define-lead'));
    expect(screen.getByTestId('leads-legend').textContent).toBe(`${LEAD_LEGEND} ${LEGEND_AUTO_HUNT}`);
    expect(screen.getByTestId('leads-note').textContent).toBe(LEADS_NOTE_AUTO_HUNT);
    fireEvent.click(screen.getByText(HOW_LEADS_WORK));
    expect(how.hasAttribute('open')).toBe(true);
  });

  it('states the manual note when auto-hunt is off', async () => {
    // Negative control: the note follows the setting.
    mount(false);
    expect((await screen.findByTestId('leads-note')).textContent).toBe(LEADS_NOTE_MANUAL);
    expect(screen.getByTestId('leads-legend').textContent).toBe(LEAD_LEGEND);
  });
});
