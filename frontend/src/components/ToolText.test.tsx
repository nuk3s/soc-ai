// Dogfood 2026-11-17, F20 and N9: text that the analyst reads showed tool
// names ("t_beacon_profile flagged 5 external pairs") and mechanics ("(tool
// the web search check:result.results)", "(skipped_field_absent)", "the
// local needs_more_info verdict"). The console shows the words of the one
// label map at display time, with what the model wrote in a tooltip.
import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { plainText, toolSegments } from '../lib/headline';
import { ORACLE_REASON } from '../lib/tooltips';
import { ToolText } from './ToolText';

describe('tool names in prose', () => {
  it('shows the words of the tool and keeps its name in the tooltip', async () => {
    render(<ToolText text="t_beacon_profile flagged 5 external pairs." />);
    const words = await screen.findByTestId('tool-words');
    expect(words.textContent).toBe('The beacon profile');
    expect(words.getAttribute('title')).toBe('The model named the tool: t_beacon_profile');
    expect(words.parentElement?.textContent).toBe('The beacon profile flagged 5 external pairs.');
  });

  it('drops the citation mechanics around a tool name', () => {
    const segs = toolSegments('reports (tool t_web_search:result.results), and the pair');
    expect(segs.map((s) => s.text).join('')).toBe('reports (the web search), and the pair');
    expect(segs.find((s) => s.tool)?.tool).toBe('tool t_web_search:result.results');
    expect(plainText('first-seen (tool t_prevalence:result.is_novel).')).toBe('first-seen (the prevalence check).');
  });

  it('keeps text with no tool name as it is', () => {
    // Negative control: a word that only starts like a tool id is no tool.
    expect(toolSegments('the host_t_x and at_risk stay')).toEqual([{ text: 'the host_t_x and at_risk stay' }]);
    expect(plainText('no tool here.')).toBe('no tool here.');
  });

  it('words the machine terms that a run copied into its text', () => {
    expect(plainText('[Oracle adjudicated] The local needs_more_info verdict is wrong.')).toBe(
      'The soc-ai needs more info verdict is wrong.',
    );
    expect(plainText('note that 192.0.2.10 (skipped_field_absent) ships no telemetry')).toBe(
      'note that 192.0.2.10 (no host name on the alert) ships no telemetry',
    );
    // Negative control: "local" in another sense stays.
    expect(plainText('a local address')).toBe('a local address');
  });

  it('names the soc-ai verdict in the reasons of an escalation', () => {
    expect(ORACLE_REASON.needs_more_info).toBe('The soc-ai verdict is Needs more info.');
    expect(Object.values(ORACLE_REASON).join(' ')).not.toMatch(/\blocal\b/);
  });
});
