import { describe, expect, it } from 'vitest';
import { cvssBaseScore } from '../../dist/deps/osv.js';

describe('cvssBaseScore', () => {
  it('scores a critical vector', () => {
    // Known CVSS 3.1 example: 9.8 (critical).
    expect(cvssBaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')).toBeCloseTo(9.8, 1);
  });

  it('scores a medium vector', () => {
    // 6.1 (medium), scope changed, reflected XSS style.
    expect(cvssBaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N')).toBeCloseTo(6.1, 1);
  });

  it('scores a low vector', () => {
    expect(cvssBaseScore('CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N')).toBeGreaterThan(0);
    expect(cvssBaseScore('CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N')!).toBeLessThan(4);
  });

  it('returns undefined for CVSS v2 or garbage', () => {
    expect(cvssBaseScore('AV:N/AC:L/Au:N/C:P/I:P/A:P')).toBeUndefined();
    expect(cvssBaseScore('not a vector')).toBeUndefined();
  });
});
