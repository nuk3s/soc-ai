// HighlightedText is the trust surface of the redaction preview: it claims
// "this exact span was redacted" over the raw analyst prompt. A highlighting
// bug (wrong span, missed span, crash on odd identifiers) misleads the
// operator about what leaves the box — so its matching rules are pinned here.
import { render } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import type { RedactionReplacement } from '../lib/api';
import { HighlightedText } from './RedactionPreviewPanel';

const rep = (value: string, label: string): RedactionReplacement => ({
  value,
  label,
  category: 'HOST',
});

/** All <mark> elements, since HighlightedText renders a bare fragment. */
function marksOf(ui: React.ReactElement): HTMLElement[] {
  const { container } = render(ui);
  return Array.from(container.querySelectorAll('mark'));
}

describe('HighlightedText', () => {
  it('marks internal values amber on the original side, with the label in the tooltip', () => {
    const marks = marksOf(
      <HighlightedText
        text="login from ws-07.corp.example failed"
        replacements={[rep('ws-07.corp.example', 'HOST_1')]}
        side="original"
      />,
    );
    expect(marks).toHaveLength(1);
    expect(marks[0]).toHaveTextContent('ws-07.corp.example');
    expect(marks[0].className).toContain('#f5a623'); // MARK_VALUE amber
    expect(marks[0]).toHaveAttribute('title', 'redacted as HOST_1');
  });

  it('marks opaque labels green on the sanitized side, naming the value they replace', () => {
    const marks = marksOf(
      <HighlightedText
        text="login from HOST_1 failed"
        replacements={[rep('ws-07.corp.example', 'HOST_1')]}
        side="sanitized"
      />,
    );
    expect(marks).toHaveLength(1);
    expect(marks[0]).toHaveTextContent('HOST_1');
    expect(marks[0].className).toContain('text-success'); // MARK_LABEL green
    expect(marks[0]).toHaveAttribute('title', 'replaces ws-07.corp.example');
  });

  it('matches longest-first so a substring value never splits the longer match', () => {
    // Shorter needle deliberately FIRST in the array — the sort must win.
    const marks = marksOf(
      <HighlightedText
        text="beacon to ws-07.corp.example observed"
        replacements={[rep('ws-07', 'HOST_1'), rep('ws-07.corp.example', 'HOST_2')]}
        side="original"
      />,
    );
    expect(marks).toHaveLength(1); // one whole-hostname mark, not ws-07 + remainder
    expect(marks[0]).toHaveTextContent('ws-07.corp.example');
    expect(marks[0]).toHaveAttribute('title', 'redacted as HOST_2');
  });

  it('matches values case-insensitively (the sanitizer lowercases host/email/MAC)', () => {
    const marks = marksOf(
      <HighlightedText
        text="user logged into WS-07.CORP.EXAMPLE"
        replacements={[rep('ws-07.corp.example', 'HOST_1')]}
        side="original"
      />,
    );
    expect(marks).toHaveLength(1);
    expect(marks[0]).toHaveTextContent('WS-07.CORP.EXAMPLE');
  });

  it('renders plain text when there is nothing to redact', () => {
    const { container } = render(
      <HighlightedText text="nothing sensitive here" replacements={[]} side="original" />,
    );
    expect(container.querySelector('mark')).toBeNull();
    expect(container).toHaveTextContent('nothing sensitive here');
  });

  it('treats regex-special characters in values literally (no crash, no wildcard match)', () => {
    // Parens/backslash would throw in an unescaped RegExp; the dots in an IP
    // would wildcard-match lookalikes.
    const marks = marksOf(
      <HighlightedText
        text="run by svc (backup) from 10.0.0.1 — not from 10a0b0c1"
        replacements={[rep('svc (backup)', 'USER_1'), rep('10.0.0.1', 'IP_1')]}
        side="original"
      />,
    );
    expect(marks).toHaveLength(2); // 10a0b0c1 must NOT match the IP needle
    expect(marks[0]).toHaveTextContent('svc (backup)');
    expect(marks[1]).toHaveTextContent('10.0.0.1');
  });
});
