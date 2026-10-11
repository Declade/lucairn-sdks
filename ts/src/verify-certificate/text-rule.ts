// Text rules of the witness-only verifier, written out so the TypeScript,
// Python and Go SDKs judge the same signature TEXT the same way instead of
// inheriting whatever each language's `trim` and base64 decoder happen to do.
//
// Module-internal: nothing in this file is re-exported from the package index.

// The white-space set: Go's `unicode.IsSpace` (which `strings.TrimSpace`
// uses) — U+0009–000D, U+0020, U+0085, U+00A0, U+1680, U+2000–200A, U+2028,
// U+2029, U+202F, U+205F, U+3000. JavaScript's `String.prototype.trim`
// differs from it on two code points: it does not trim U+0085 and it does
// trim U+FEFF.
const WHITE_SPACE = new Set<number>([
  0x0009, 0x000a, 0x000b, 0x000c, 0x000d, 0x0020, 0x0085, 0x00a0, 0x1680,
  0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200a,
  0x2028, 0x2029, 0x202f, 0x205f, 0x3000,
]);

/** True when a signature field is empty or holds only white space of the set above. */
export function isBlankSignatureText(text: string): boolean {
  // Every member of the set is one UTF-16 code unit.
  for (let i = 0; i < text.length; i++) {
    if (!WHITE_SPACE.has(text.charCodeAt(i))) return false;
  }
  return true;
}

/**
 * Decodes a signature field. The text must be CANONICAL standard padded
 * base64 (alphabet `A-Z a-z 0-9 + /`, `=` padding, nothing else): decode,
 * re-encode, compare. Returns null for anything else — unpadded or URL-safe
 * text, embedded white space, non-zero padding bits, trailing characters —
 * all of which `Buffer.from(text, 'base64')` would silently accept.
 */
export function decodeSignatureText(text: string): Uint8Array | null {
  const raw = Buffer.from(text, 'base64');
  return raw.toString('base64') === text ? new Uint8Array(raw) : null;
}
