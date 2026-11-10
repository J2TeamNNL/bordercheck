// Random secrets handed out by the receiver (invite codes, machine tokens,
// report-link ids) and how they are kept: only their SHA-256 is stored. They
// are 128 to 256 bits from the CSPRNG, so a plain hash is enough (there is
// nothing to brute-force that a slow hash would protect), and lookups by hash
// reveal nothing useful through timing: an attacker would need a preimage.

const enc = new TextEncoder();

export function b64url(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function randomB64url(nBytes: number): string {
  return b64url(crypto.getRandomValues(new Uint8Array(nBytes)));
}

export function randomHex(nBytes: number): string {
  return [...crypto.getRandomValues(new Uint8Array(nBytes))].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export async function sha256hex(s: string): Promise<string> {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(s)));
  return [...d].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// Invite code: 32 random bytes, base64url without padding (43 characters).
export const CODE_RE = /^[A-Za-z0-9_-]{43}$/;
export const newCode = () => randomB64url(32);

// Machine token: a recognisable prefix (for secret scanners) and 32 random bytes.
export const TOKEN_PREFIX = "bcm_";
export const TOKEN_RE = /^bcm_[A-Za-z0-9_-]{43}$/;
export const newToken = () => TOKEN_PREFIX + randomB64url(32);

// Install IDs of enrolled machines: 16 random bytes as 32 hex.
export const newInstallId = () => randomHex(16);

// Report-link id: 24 random bytes (192 bits), base64url (32 characters).
export const LINK_RE = /^[A-Za-z0-9_-]{32}$/;
export const newLinkId = () => randomB64url(24);
