// Hunt-fit batch: the template picker (a) polls itself so amber clears without
// a reload, and (b) renders THREE distinct states — normal, missing-telemetry
// (amber, a fixable gap), and not-applicable (demoted into a collapsed cluster,
// grayed, never hidden, still runnable). The demotion must never become
// blindness: a demoted chip launches exactly like any other.
import { act, fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { DemoProvider } from '../lib/demo';
import type { HuntTemplate } from '../lib/api';

const getHuntTemplatesMock = vi.hoisted(() => vi.fn());
const startHuntConsoleMock = vi.hoisted(() => vi.fn());

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getHunts: vi.fn().mockResolvedValue([]),
  getHuntStats: vi.fn().mockResolvedValue([]),
  getHuntSchedules: vi.fn().mockResolvedValue({ schedules: [], masterSwitchEnabled: true }),
  getHuntTemplates: getHuntTemplatesMock,
  startHuntConsole: startHuntConsoleMock,
}));

import { Hunts } from './Hunts';

// `availabilityKnown` is optional on the shared type, so a payload from a
// server predating the degraded-grid round reads as "known" — which is what it
// was. The fixtures below that care about the axis set it explicitly.
type Template = HuntTemplate;

let nextId = 1;
function tpl(over: Partial<Template>): Template {
  return {
    id: nextId++,
    name: 'A template',
    objectiveTemplate: 'Hunt for something.',
    requiredDatasets: [],
    defaultWindowMinutes: 1440,
    builtin: true,
    createdBy: 'system',
    createdAt: '2026-08-01T00:00:00+00:00',
    available: true,
    missingDatasets: [],
    applicable: true,
    missingEnvironment: [],
    ...over,
  };
}

function renderHunts() {
  return render(
    <MemoryRouter initialEntries={['/hunts']}>
      <DemoProvider demo={false}>
        <Routes>
          <Route path="/hunts" element={<Hunts />} />
          <Route path="/hunts/:id" element={<div>HUNT DETAIL</div>} />
        </Routes>
      </DemoProvider>
    </MemoryRouter>,
  );
}

afterEach(() => {
  getHuntTemplatesMock.mockReset();
  startHuntConsoleMock.mockReset();
});

describe('TemplatePicker auto-refresh', () => {
  it('re-fetches the template list on the 60s poll (house fake-timer pattern)', async () => {
    getHuntTemplatesMock.mockResolvedValue([tpl({ name: 'Beaconing to rare IPs' })]);
    vi.useFakeTimers();
    try {
      renderHunts();
      // flush the initial foreground load
      await act(async () => {
        await vi.advanceTimersByTimeAsync(0);
      });
      expect(getHuntTemplatesMock).toHaveBeenCalledTimes(1);

      await act(async () => {
        await vi.advanceTimersByTimeAsync(60_000);
      });
      expect(getHuntTemplatesMock).toHaveBeenCalledTimes(2);

      await act(async () => {
        await vi.advanceTimersByTimeAsync(60_000);
      });
      expect(getHuntTemplatesMock).toHaveBeenCalledTimes(3);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe('TemplatePicker three-state catalogue', () => {
  const THREE: Template[] = [
    tpl({ name: 'Beaconing to rare IPs', objectiveTemplate: 'Hunt for beaconing.' }),
    tpl({
      name: 'DNS / C2 exfiltration',
      objectiveTemplate: 'Hunt for DNS tunneling.',
      available: false,
      missingDatasets: ['zeek.dns'],
    }),
    tpl({
      name: 'Lateral movement',
      objectiveTemplate: 'Hunt for lateral movement.',
      applicable: false,
      missingEnvironment: ['a Windows host'],
    }),
  ];

  it('renders normal + amber chips inline and demotes not-applicable into a collapsed cluster', async () => {
    getHuntTemplatesMock.mockResolvedValue(THREE);
    renderHunts();

    // Wait for the TEMPLATE-fed render (the fallback pills paint first, while
    // the fetch is in flight, and share names with the builtins) — the cluster
    // expander only exists once real templates are in.
    const expander = await screen.findByText(/Not applicable here · 1/);

    // normal chip: plain objective tooltip, no warning copy
    const normal = screen.getByText('Beaconing to rare IPs');
    expect(normal.closest('button')!.getAttribute('title')).toBe('Hunt for beaconing.');

    // amber chip: the existing missing-telemetry copy (a FIXABLE gap)
    const amber = screen.getByText('DNS / C2 exfiltration');
    expect(amber.closest('button')!.getAttribute('title')).toContain(
      'missing telemetry: zeek.dns',
    );

    // demoted chip: NOT in the strip until the cluster is expanded
    expect(screen.queryByText('Lateral movement')).toBeNull();
    fireEvent.click(expander);

    const demoted = screen.getByText('Lateral movement');
    const title = demoted.closest('button')!.getAttribute('title')!;
    expect(title).toContain('Needs a Windows host — none observed on this network.');
    expect(title).toContain('Re-checked after every dossier sweep.');
    expect(title).toContain('Still runnable.');

    // collapsing hides it again
    fireEvent.click(expander);
    expect(screen.queryByText('Lateral movement')).toBeNull();
  });

  it('a demoted chip still fills the objective and launches the hunt', async () => {
    getHuntTemplatesMock.mockResolvedValue(THREE);
    startHuntConsoleMock.mockResolvedValue({ hunt_id: 'h-99' });
    renderHunts();

    fireEvent.click(await screen.findByText(/Not applicable here · 1/));
    fireEvent.click(screen.getByText('Lateral movement'));

    const box = screen.getByPlaceholderText(/hunt for beaconing to rare external IPs/i);
    expect((box as HTMLTextAreaElement).value).toBe('Hunt for lateral movement.');

    fireEvent.click(screen.getByText('Start hunt'));
    expect(startHuntConsoleMock).toHaveBeenCalledWith('Hunt for lateral movement.');
    expect(await screen.findByText('HUNT DETAIL')).toBeTruthy();
  });
});

describe('TemplatePicker fallback presets (template service unreachable)', () => {
  it('shows one muted availability-unknown note beside the static pills', async () => {
    getHuntTemplatesMock.mockRejectedValue(new Error('api down'));
    renderHunts();

    // the six static pills still render (the picker never vanishes) …
    expect(await screen.findAllByText('Beaconing to rare IPs')).toBeTruthy();
    // … under a single un-annotated note, not per-pill flags.
    //
    // findBy, not getBy: the pills are the STATIC fallback and paint on first
    // render, while the note waits on the rejected fetch settling. The await
    // above can therefore resolve a tick before the note exists, and a
    // synchronous getBy then loses the race — which is what it did on CI when
    // two pipelines shared the one runner, failing with "Unable to find an
    // element with the text: /availability unknown…/" while passing on every
    // idle box and on five local reruns.
    expect(
      await screen.findByText(/availability unknown while the template service is unreachable/i),
    ).toBeTruthy();
  });

  it('does not show the note when templates load', async () => {
    getHuntTemplatesMock.mockResolvedValue([tpl({ name: 'Beaconing to rare IPs' })]);
    renderHunts();

    await screen.findByText('Beaconing to rare IPs');
    expect(
      screen.queryByText(/availability unknown while the template service is unreachable/i),
    ).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// D14 (degraded-grid dogfood) — the FOURTH state, and the one that was silently
// collapsed into the first. On a half-read grid GET /hunt-templates answers 200
// with the availability axis unevaluated ("hunt-template availability: inventory
// discovery failed"), so every template comes back available=true — fail-open,
// which is right, and indistinguishable from a measured yes, which is not. The
// picker drew six confident accent chips and dropped the legend, and a hunt got
// launched against telemetry the grid could not read.
//
// The fallback caption above is not this case: there the FETCH failed. Here the
// list is real and only the annotation is missing.
// ---------------------------------------------------------------------------

const UNKNOWN_CAPTION = /availability unknown — the grid inventory could not be read/i;

describe('TemplatePicker availability unknown (inventory unreadable)', () => {
  const UNCHECKED: Template[] = [
    tpl({ name: 'Beaconing to rare IPs', availabilityKnown: false }),
    tpl({ name: 'DNS / C2 exfiltration', availabilityKnown: false }),
  ];

  it('says the axis was never evaluated instead of dropping the annotation', async () => {
    getHuntTemplatesMock.mockResolvedValue(UNCHECKED);
    renderHunts();

    // findBy, not getBy: the static fallback pills paint on first render and
    // share names with the builtins, so the caption has to be what we wait on.
    expect(await screen.findByText(UNKNOWN_CAPTION)).toBeTruthy();
  });

  it('lets no chip claim the grid is seeing its telemetry', async () => {
    getHuntTemplatesMock.mockResolvedValue(UNCHECKED);
    const { container } = renderHunts();
    await screen.findByText(UNKNOWN_CAPTION);

    const chips = container.querySelectorAll('[data-availability]');
    expect(chips.length).toBe(UNCHECKED.length); // the selector matches something
    for (const chip of chips) {
      expect(chip.getAttribute('data-availability')).toBe('unknown');
      expect(chip.getAttribute('title')).toContain('Availability unknown');
    }
  });

  it('drops the legend whose claim the unread inventory cannot support', async () => {
    getHuntTemplatesMock.mockResolvedValue(UNCHECKED);
    renderHunts();
    await screen.findByText(UNKNOWN_CAPTION);

    expect(screen.queryByText(/highlighted templates match telemetry/i)).toBeNull();
  });

  it('keeps the amber flag and the legend on a HEALTHY grid', async () => {
    // The over-correction guard. "Unknown" and "unavailable" are different
    // states: a template the server CHECKED and found unbacked must keep its
    // warning glyph and the legend that contrasts it, or this fix trades a
    // false all-clear for a permanent shrug.
    getHuntTemplatesMock.mockResolvedValue([
      tpl({ name: 'Beaconing to rare IPs' }),
      tpl({ name: 'DNS / C2 exfiltration', available: false, missingDatasets: ['zeek.dns'] }),
    ]);
    const { container } = renderHunts();

    expect(await screen.findByText(/highlighted templates match telemetry/i)).toBeTruthy();
    expect(screen.queryByText(UNKNOWN_CAPTION)).toBeNull();

    const states = [...container.querySelectorAll('[data-availability]')].map((c) =>
      c.getAttribute('data-availability'),
    );
    expect(states).toEqual(['available', 'missing']);
  });
});
