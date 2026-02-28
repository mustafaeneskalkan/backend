import crypto from 'crypto';

function getHashSecret(): string {
  const secret = process.env.REFRESH_TOKEN_HASH_SECRET || process.env.JWT_REFRESH_SECRET;
  if (!secret) {
    throw new Error('REFRESH_TOKEN_HASH_SECRET or JWT_REFRESH_SECRET must be configured');
  }
  return secret;
}

export function hashRefreshToken(token: string): string {
  const secret = getHashSecret();
  return crypto.createHmac('sha256', secret).update(token).digest('hex');
}

export function safeEqualHex(a: string, b: string): boolean {
  try {
    const aBuf = Buffer.from(a, 'hex');
    const bBuf = Buffer.from(b, 'hex');
    if (aBuf.length !== bBuf.length) return false;
    return crypto.timingSafeEqual(aBuf, bBuf);
  } catch {
    return false;
  }
}
