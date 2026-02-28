describe('token-hash', () => {
  it('hashRefreshToken returns sha256 hex', async () => {
    process.env.REFRESH_TOKEN_HASH_SECRET = 'secret';
    const { hashRefreshToken } = await import('../../src/utils/token-hash.js');
    const hash = hashRefreshToken('token');
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it('safeEqualHex compares constant-time and rejects invalid hex', async () => {
    const { safeEqualHex } = await import('../../src/utils/token-hash.js');
    expect(safeEqualHex('aa', 'aa')).toBe(true);
    expect(safeEqualHex('aa', 'ab')).toBe(false);
    expect(safeEqualHex('not-hex', 'aa')).toBe(false);
    expect(safeEqualHex('aa', 'aabb')).toBe(false);
  });
});
