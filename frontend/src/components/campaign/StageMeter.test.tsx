import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import type { CampaignStage } from '../../lib/api';
import { STAGE_COLOR, STAGE_SEQUENCE } from '../../lib/campaignViz';
import { forbiddenWords } from '../../test/analystWords';
import { StageMeter } from './StageMeter';

function segments(): HTMLElement[] {
  return Array.from(screen.getByTestId('stage-meter').children) as HTMLElement[];
}

describe('StageMeter', () => {
  it('fills the segments up to the reached stage, each in the color of its stage', () => {
    render(<StageMeter stage="access" />);
    const parts = segments();
    expect(parts).toHaveLength(5);
    expect(parts.map((p) => p.getAttribute('data-filled'))).toEqual(['true', 'true', 'true', 'false', 'false']);
    parts.slice(0, 3).forEach((p, i) => expect(p.style.background).toBe(STAGE_COLOR[STAGE_SEQUENCE[i]]));
    // The other segments wear the muted surface and no stage color.
    for (const p of parts.slice(3)) {
      expect(p.style.background).toBe('');
      expect(p.className).toContain('bg-border-strong');
    }
  });

  it('states the stage and its place in the sequence as its accessible name and hover text', () => {
    render(<StageMeter stage="access" />);
    const meter = screen.getByRole('img', { name: 'Stage reached: Access, 3 of 5' });
    expect(meter).toHaveAttribute('title', 'Stage reached: Access, 3 of 5');
    expect(meter).toHaveAttribute('data-stage', 'access');
  });

  it('fills all five segments for movement beyond the target', () => {
    render(<StageMeter stage="movement" />);
    expect(segments().every((p) => p.getAttribute('data-filled') === 'true')).toBe(true);
    expect(screen.getByRole('img')).toHaveAccessibleName('Stage reached: Movement beyond the target, 5 of 5');
  });

  // NEGATIVE CONTROL. A campaign with no proven stage fills no segment.
  it('fills no segment and says "No proven stage" with no stage', () => {
    for (const stage of [null, undefined]) {
      const { unmount } = render(<StageMeter stage={stage} />);
      expect(segments().some((p) => p.getAttribute('data-filled') === 'true')).toBe(false);
      expect(screen.getByRole('img')).toHaveAccessibleName('No proven stage');
      unmount();
    }
  });

  // A stage from a newer server reads as its own word and fills no segment.
  it('names a stage off the sequence and fills no segment', () => {
    render(<StageMeter stage={'exfiltration' as CampaignStage} />);
    expect(segments().some((p) => p.getAttribute('data-filled') === 'true')).toBe(false);
    expect(screen.getByRole('img')).toHaveAccessibleName('Stage reached: exfiltration');
  });

  it('holds no forbidden word', () => {
    const { container } = render(<StageMeter stage="action" />);
    expect(forbiddenWords(container)).toEqual([]);
  });
});
