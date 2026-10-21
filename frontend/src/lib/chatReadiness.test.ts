// What the chat surfaces say about the model gateway and the grid (H1-D13).
import { describe, expect, it } from 'vitest';
import type { Health } from './api';
import { chatReadiness } from './chatReadiness';

const up = { ok: true, detail: 'ok' };
const down = { ok: false, detail: 'Connection refused' };
const slow = { ok: false, detail: 'answered in 4.3 s', kind: 'slow' };

const health = (over: Partial<Health>): Health => ({ es: up, llm: up, so: up, ...over }) as Health;

describe('chatReadiness', () => {
  it('blocks a send while the model gateway is down', () => {
    const r = chatReadiness(health({ llm: down }));
    expect(r.blocked).toBe(
      'The model gateway does not answer. soc-ai cannot answer a question until the gateway answers.',
    );
  });

  it('notes a down grid and keeps the send', () => {
    const r = chatReadiness(health({ es: down }));
    expect(r.blocked).toBeNull();
    expect(r.note).toBe('The grid does not answer. An answer can use only the records soc-ai stores.');
  });

  it('says both when both are down', () => {
    const r = chatReadiness(health({ es: down, llm: down }));
    expect(r.blocked).toMatch(/model gateway does not answer/);
    expect(r.note).toMatch(/grid does not answer/);
  });

  it('notes a slow gateway and keeps the send', () => {
    const r = chatReadiness(health({ llm: slow }));
    expect(r.blocked).toBeNull();
    expect(r.note).toBe('The model gateway is slow. An answer can take longer.');
  });

  it('says nothing for a healthy or an unknown state', () => {
    expect(chatReadiness(health({}))).toEqual({ blocked: null, note: null });
    // A failed /health read says nothing about the dependencies.
    expect(chatReadiness(null)).toEqual({ blocked: null, note: null });
  });
});
