import { describe, expect, it } from 'vitest';
import { safeUrl } from './Markdown';

// Agent markdown is derived from attacker-influenced data (payloads, hostnames,
// rule names), so link hrefs are untrusted. safeUrl pins the allow-list in code
// so link safety no longer depends on react-markdown's default urlTransform.
describe('safeUrl', () => {
  it('allows http/https/mailto', () => {
    expect(safeUrl('http://example.com')).toBe('http://example.com');
    expect(safeUrl('https://example.com/x?y=1#z')).toBe('https://example.com/x?y=1#z');
    expect(safeUrl('mailto:soc@example.com')).toBe('mailto:soc@example.com');
    // Scheme casing is normalized for the check, value is preserved.
    expect(safeUrl('HTTPS://example.com')).toBe('HTTPS://example.com');
  });

  it('allows scheme-less relative and anchor targets', () => {
    expect(safeUrl('/ui/alerts')).toBe('/ui/alerts');
    expect(safeUrl('#section')).toBe('#section');
    expect(safeUrl('foo/bar')).toBe('foo/bar');
    expect(safeUrl('?q=1')).toBe('?q=1');
  });

  it('drops dangerous schemes', () => {
    expect(safeUrl('javascript:alert(1)')).toBe('');
    expect(safeUrl('JavaScript:alert(1)')).toBe('');
    expect(safeUrl('data:text/html,<script>alert(1)</script>')).toBe('');
    expect(safeUrl('vbscript:msgbox(1)')).toBe('');
    expect(safeUrl('file:///etc/passwd')).toBe('');
  });

  it('treats a colon after the first path/query/hash char as non-scheme', () => {
    // Here the ':' is part of the path, not a scheme delimiter → safe relative URL.
    expect(safeUrl('/path:with:colons')).toBe('/path:with:colons');
    expect(safeUrl('foo?x=a:b')).toBe('foo?x=a:b');
  });
});
