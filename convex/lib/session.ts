const SESSION_TOKEN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export function anonymousOwnerKey(sessionToken: string) {
  const normalized = sessionToken.trim().toLowerCase();
  if (!SESSION_TOKEN.test(normalized)) throw new Error("Invalid anonymous session.");
  return `anonymous:${normalized}`;
}
