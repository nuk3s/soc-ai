// One kind had three names. The leads strip read "analytic matched", the lead
// page read "catalog match" and the host page read "finding" for a kind whose
// real label is "finding with no benign baseline". An analyst reading a lead
// beside a host page saw two products.
import { describe, expect, it } from 'vitest';

import { KIND_LABEL, kindLabel, sourceLabel, sourceTitle } from './kinds';

describe('kindLabel', () => {
  it('names the kinds a lead can hold', () => {
    expect(kindLabel('novel_destination')).toBe('new destination');
    expect(kindLabel('novel_binding')).toBe('first logon here');
    expect(kindLabel('below_baseline')).toBe('rate collapsed');
    expect(kindLabel('above_baseline')).toBe('rate spiked');
    expect(kindLabel('scope_count')).toBe('across many hosts');
    expect(kindLabel('prior_no_baseline')).toBe('finding with no benign baseline');
    expect(kindLabel('catalog_match')).toBe('analytic match');
    expect(kindLabel('hunt_finding')).toBe('hunt finding');
  });

  it('prefers the label the API sends', () => {
    expect(kindLabel('catalog_match', 'a Kerberos ticket for a service account')).toBe(
      'a Kerberos ticket for a service account',
    );
  });

  it('reads an unknown kind as its own word rather than as nothing', () => {
    expect(kindLabel('brand_new_kind')).toBe('brand new kind');
    expect(kindLabel('brand_new_kind', null)).toBe('brand new kind');
    expect(kindLabel('brand_new_kind', '')).toBe('brand new kind');
  });

  it('holds one label per kind and no duplicate', () => {
    const labels = Object.values(KIND_LABEL);
    expect(new Set(labels).size).toBe(labels.length);
  });
});

describe('sourceLabel', () => {
  it('maps the legacy candidate word to catalog', () => {
    expect(sourceLabel('candidate')).toBe('catalog');
    expect(sourceTitle('candidate')).toContain('catalog sweep');
  });

  it('reads a shadow observation as shadow whatever wrote it', () => {
    expect(sourceLabel('profile', true)).toBe('shadow');
    expect(sourceLabel('candidate', true)).toBe('shadow');
    expect(sourceTitle('candidate', true)).toContain('catalog observation');
  });

  it('keeps the live sources', () => {
    expect(sourceLabel('profile')).toBe('profile');
    expect(sourceLabel('catalog')).toBe('catalog');
    expect(sourceLabel('alert')).toBe('alert');
    expect(sourceLabel('hunt')).toBe('hunt');
  });
});
