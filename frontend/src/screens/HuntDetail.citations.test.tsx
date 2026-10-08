// Dogfood 2026-10-06 K4: finding citations showed tool names,
// "t_origin_chain(10.99.0.40)", as document chips that opened nothing.
import { render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import type { AboutInfo, HuntDetailData } from '../lib/types';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getHunt: vi.fn(),
  getHunts: vi.fn().mockResolvedValue([]),
  getLead: vi.fn(),
  getHuntChat: vi.fn().mockResolvedValue({ messages: [], pending: false }),
  postHuntChat: vi.fn(),
  getAbout: vi.fn(),
}));

import { getAbout, getHunt } from '../lib/api';
import { HuntDetail, citationWords } from './HuntDetail';

const about: AboutInfo = {
  version: '1.0.0',
  repo_url: 'https://example.test/soc-ai',
  license: 'MIT',
  update_check_enabled: false,
  general_chat_enabled: true,
  sigma_authoring_enabled: false,
};

describe('finding citations in words', () => {
  it('names a tool citation in words', () => {
    expect(citationWords('t_origin_chain(10.99.0.40)')).toBe('Origin chain of 10.99.0.40');
    expect(citationWords('t_decode_payload(doc_id="abc123")')).toBe('Decoded payload of abc123');
    expect(citationWords('t_host_dossier(10.1.10.11)')).toBe('Host dossier of 10.1.10.11');
    expect(citationWords('t_new_tool(x)')).toBe('New tool of x');
    // Negative control: a document id stays a document id.
    expect(citationWords('tel-doc-000001')).toBeNull();
    expect(citationWords('AZK3x9_tq7')).toBeNull();
  });

  it('renders the words and keeps the document chip for a document', async () => {
    vi.mocked(getAbout).mockResolvedValue(about);
    const hunt: HuntDetailData = {
      id: 'H-16',
      objective: 'hunt for id',
      kind: 'chat',
      status: 'complete',
      narrative: '',
      findings: [
        {
          title: 'HTTP service executes id command as root',
          detail: 'd',
          severity: 'medium',
          category: 'threat',
          hosts: [],
          citations: ['t_origin_chain(10.99.0.40)', 'tel-doc-000001'],
        },
      ],
      affectedHosts: [],
      mitreTechniques: [],
      recommendedActions: [],
      confidence: 0.7,
      startedBy: 'analyst',
      elapsedLabel: '6m',
      elapsedSec: 360,
      ts: '2026-10-06T00:00:00Z',
      timeline: [],
      diff: null,
      outcome: 'threat_found',
    };
    vi.mocked(getHunt).mockResolvedValue(hunt);
    render(
      <MemoryRouter initialEntries={['/hunts/H-16']}>
        <Routes>
          <Route path="/hunts/:id" element={<HuntDetail />} />
        </Routes>
      </MemoryRouter>,
    );
    const words = await screen.findByTestId('citation-words');
    expect(words.textContent).toBe('Origin chain of 10.99.0.40');
    expect(screen.queryByText('t_origin_chain(10.99.0.40)')).toBeNull();
    expect(screen.getByText('tel-doc-000001')).toBeInTheDocument();
  });
});
