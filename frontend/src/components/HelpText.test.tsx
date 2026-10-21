// HelpText renders a help string from the backend. The dogfood of 2026-10-19
// (R5-D17, R5-D18) found raw markdown backticks on 11 help strings and
// "above" and "below" references to panels in other sections, which the
// one-section-at-a-time Settings page never shows together. HelpText turns a
// `code` span into a <code> element and a "Settings > <Section title>"
// reference into a link to that section.
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';
import { HelpText, SETTINGS_SECTION_TITLES, sectionIdFor, sectionIdsFromLayout } from './HelpText';
import { buildConfigLayout } from '../lib/configLayout';

function renderHelp(text: string | null | undefined, sections?: Record<string, string>) {
  return render(
    <MemoryRouter>
      <HelpText text={text} sections={sections} />
    </MemoryRouter>,
  );
}

describe('HelpText', () => {
  it('renders plain text as it is', () => {
    const { container } = renderHelp('The sweep makes no model call.');
    expect(container.textContent).toBe('The sweep makes no model call.');
    expect(container.querySelector('code')).toBeNull();
    expect(container.querySelector('a')).toBeNull();
  });

  it('renders nothing for an empty or absent string', () => {
    for (const text of ['', null, undefined]) {
      const { container, unmount } = renderHelp(text);
      expect(container.textContent).toBe('');
      unmount();
    }
  });

  it('turns a backtick span into a code element without the backticks', () => {
    const { container } = renderHelp('Run `soc-ai blocklists refresh` once a day.');
    const code = container.querySelector('code');
    expect(code?.textContent).toBe('soc-ai blocklists refresh');
    expect(container.textContent).toBe('Run soc-ai blocklists refresh once a day.');
    expect(container.textContent).not.toContain('`');
  });

  it('turns every code span of a string into its own code element', () => {
    const { container } = renderHelp('Set `a` and `b`.');
    expect([...container.querySelectorAll('code')].map((c) => c.textContent)).toEqual(['a', 'b']);
  });

  it('keeps an unpaired backtick as text', () => {
    const { container } = renderHelp('A lone ` mark stays.');
    expect(container.querySelector('code')).toBeNull();
    expect(container.textContent).toBe('A lone ` mark stays.');
  });

  it('links a reference to a standalone panel by its fixed id', () => {
    renderHelp('Set the provider keys in Settings > API keys.');
    const link = screen.getByRole('link', { name: 'Settings > API keys' });
    expect(link.getAttribute('href')).toBe('/config#api-keys');
  });

  it('links a reference to a server settings section by its slug', () => {
    renderHelp('Set the MISP URL in Settings > Online enrichment. Then restart soc-ai.');
    const link = screen.getByRole('link', { name: 'Settings > Online enrichment' });
    expect(link.getAttribute('href')).toBe('/config#online-enrichment');
  });

  it('links a section title that holds punctuation', () => {
    renderHelp('See Settings > Retrieval (RAG).');
    expect(screen.getByRole('link', { name: 'Settings > Retrieval (RAG)' }).getAttribute('href')).toBe(
      '/config#retrieval-rag',
    );
  });

  it('prefers the longest title at the reference', () => {
    // "Notifications" is a server section and "Notification webhook" a panel.
    renderHelp('Set it in Settings > Notification webhook.');
    expect(screen.getByRole('link').getAttribute('href')).toBe('/config#notifications-webhook');
  });

  it('keeps an unknown section as plain text', () => {
    const { container } = renderHelp('Set it in Settings > Nowhere at all.');
    expect(container.querySelector('a')).toBeNull();
    expect(container.textContent).toBe('Set it in Settings > Nowhere at all.');
  });

  it('keeps a title that only starts the next word as plain text', () => {
    // "Agent" is a section. "Agentic" is no reference to it.
    const { container } = renderHelp('Settings > Agentic reads nothing.');
    expect(container.querySelector('a')).toBeNull();
  });

  it('never links inside a code span', () => {
    const { container } = renderHelp('Type `Settings > API keys` in the box.');
    expect(container.querySelector('a')).toBeNull();
    expect(container.querySelector('code')?.textContent).toBe('Settings > API keys');
  });

  it('mixes a code span and a link in one string', () => {
    const { container } = renderHelp('Run `soc-ai doctor`. Then open Settings > Diagnostics.');
    expect(container.querySelector('code')?.textContent).toBe('soc-ai doctor');
    expect(screen.getByRole('link').getAttribute('href')).toBe('/config#diagnostics');
    expect(container.textContent).toBe('Run soc-ai doctor. Then open Settings > Diagnostics.');
  });

  it('uses a caller map of section ids when one is given', () => {
    renderHelp('Open Settings > Custom place.', { 'Custom place': 'custom-id' });
    expect(screen.getByRole('link').getAttribute('href')).toBe('/config#custom-id');
  });

  it('keeps a section name as plain text outside a router', () => {
    const { container } = render(<HelpText text="Open Settings > API keys. Run `x`." />);
    expect(container.querySelector('a')).toBeNull();
    expect(container.querySelector('code')?.textContent).toBe('x');
    expect(container.textContent).toBe('Open Settings > API keys. Run x.');
  });

  it('derives the same ids that the Config layout renders', () => {
    const groups = SETTINGS_SECTION_TITLES.map((title) => ({ title, parent: 'Models & Reasoning', items: [] }));
    const fromLayout = sectionIdsFromLayout(buildConfigLayout(groups));
    for (const title of SETTINGS_SECTION_TITLES) {
      expect(sectionIdFor(title)).toBe(fromLayout[title]);
    }
    expect(fromLayout['API keys']).toBe('api-keys');
  });
});
