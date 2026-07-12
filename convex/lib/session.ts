const SESSION_TOKEN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const NONCE = /^\d{1,10}$/;

async function digestHex(value: string) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function normalizedSessionToken(sessionToken: string) {
  const normalized = sessionToken.trim().toLowerCase();
  if (!SESSION_TOKEN.test(normalized)) throw new Error("Invalid anonymous session.");
  return normalized;
}

export async function anonymousOwnerKey(sessionToken: string) {
  const secret = process.env.ANONYMOUS_SESSION_SECRET;
  if (!secret) throw new Error("Anonymous scanning is not configured.");
  return `anonymous:${await digestHex(`${secret}:${normalizedSessionToken(sessionToken)}`)}`;
}

export async function verifyAuditProof(sessionToken: string, scanId: string, nonce: string) {
  if (!NONCE.test(nonce)) return false;
  const digest = await digestHex(`${normalizedSessionToken(sessionToken)}:${scanId}:${nonce}`);
  return digest.startsWith("00") && Number.parseInt(digest[2], 16) < 4;
}
