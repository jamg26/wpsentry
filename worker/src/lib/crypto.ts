// Password hashing via PBKDF2-SHA256 (Web Crypto — no external deps)

const ITERATIONS = 100_000; // Cloudflare Workers max
const KEY_LENGTH = 32; // bytes
const SALT_LENGTH = 16; // bytes

export async function hashPassword(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
  const key = await deriveKey(password, salt);
  const saltHex = toHex(salt);
  const keyHex = toHex(new Uint8Array(key));
  return `pbkdf2:${ITERATIONS}:${saltHex}:${keyHex}`;
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  try {
    const [, iters, saltHex, keyHex] = stored.split(':');
    const salt = fromHex(saltHex);
    const expectedKey = fromHex(keyHex);
    const actualKey = await deriveKey(password, salt, parseInt(iters, 10));
    return timingSafeEqual(new Uint8Array(actualKey), expectedKey);
  } catch {
    return false;
  }
}

async function deriveKey(password: string, salt: Uint8Array, iterations = ITERATIONS): Promise<ArrayBuffer> {
  const baseKey = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    'PBKDF2',
    false,
    ['deriveBits'],
  );
  return crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    baseKey,
    KEY_LENGTH * 8,
  );
}

function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

function toHex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function fromHex(hex: string): Uint8Array {
  const arr = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    arr[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return arr;
}

/** Constant-time string comparison (hashes both to normalize length). */
export async function timingSafeEqualStrings(a: string, b: string): Promise<boolean> {
  const encoder = new TextEncoder();
  const [hashA, hashB] = await Promise.all([
    crypto.subtle.digest('SHA-256', encoder.encode(a)),
    crypto.subtle.digest('SHA-256', encoder.encode(b)),
  ]);
  return timingSafeEqual(new Uint8Array(hashA), new Uint8Array(hashB));
}

export function generateId(length = 21): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  return [...bytes].map((b) => chars[b % chars.length]).join('');
}

/** Generate a new API key in the format jwp_live_{32 random chars}. */
export function generateApiKey(): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  const random = [...bytes].map((b) => chars[b % chars.length]).join('');
  return `jwp_live_${random}`;
}

/** SHA-256 hex digest of a string (for API key storage). */
export async function sha256Hex(input: string): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** HMAC-SHA256 hex signature over body using secret. */
export async function hmacSha256Hex(secret: string, body: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(body));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

