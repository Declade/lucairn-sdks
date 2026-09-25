// Strict JSON with number lexemes kept, and the canonical encoder the Lucairn
// producers sign with — parity corpus README § Input document and § Canonical
// JSON (Declade/dual-sandbox-architecture tools/parity-corpus/README.md).
//
// JSON.parse cannot be used: it turns numbers into doubles (2.0000000000000001
// becomes 2, 0.0 re-prints as 0, a 5,000-digit integer loses its digits), and
// the recipe reads integer TOKENS and rebuilds signed bytes from the original
// number text. Objects are Maps so a key like "__proto__" is plain data.

/** A JSON number kept as its source lexeme. */
export class JNum {
  constructor(readonly text: string) {}
}

export type JVal = null | boolean | string | JNum | JVal[] | JObj;
export type JObj = Map<string, JVal>;

// Nesting bound (arrays/objects). The Python and Go SDKs enforce the same
// bound, so all three decide deep documents alike; real certificates nest
// fewer than 10 levels.
export const MAX_DEPTH = 256;

// An escaped UTF-16 surrogate that is not part of a pair reads as U+FFFD, as
// Go's encoding/json (the witness) decodes it; the Python and Go SDKs agree.
const LONE_SURROGATE = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/g;

export class JsonGrammarError extends Error {}

const NUMBER_RE = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;

/**
 * Parse exactly ONE RFC 8259 JSON value followed only by JSON whitespace
 * (space, tab, LF, CR). A byte-order mark, NaN / Infinity, a second value or
 * stray trailing bytes are errors. Bytes must be valid UTF-8.
 */
export function parseDocument(input: string | Uint8Array): JVal {
  let s: string;
  if (typeof input === 'string') {
    s = input;
  } else {
    try {
      // fatal: invalid UTF-8 throws; ignoreBOM: a BOM stays in the text, where
      // the grammar refuses it (no encoding sniffing).
      s = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(input);
    } catch {
      throw new JsonGrammarError('not UTF-8');
    }
  }
  const p = new Parser(s);
  p.ws();
  const v = p.value(0);
  p.ws();
  if (p.i !== s.length) throw new JsonGrammarError(`trailing data at ${p.i}`);
  return v;
}

class Parser {
  i = 0;
  constructor(private readonly s: string) {}

  ws(): void {
    const s = this.s;
    while (this.i < s.length) {
      const c = s.charCodeAt(this.i);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) this.i++;
      else break;
    }
  }

  value(depth: number): JVal {
    const s = this.s;
    const c = s[this.i];
    if (c === '{') return this.object(depth + 1);
    if (c === '[') return this.array(depth + 1);
    if (c === '"') return this.string();
    if (s.startsWith('true', this.i)) {
      this.i += 4;
      return true;
    }
    if (s.startsWith('false', this.i)) {
      this.i += 5;
      return false;
    }
    if (s.startsWith('null', this.i)) {
      this.i += 4;
      return null;
    }
    NUMBER_RE.lastIndex = this.i;
    const m = NUMBER_RE.exec(s);
    if (m && m[0].length > 0) {
      this.i += m[0].length;
      return new JNum(m[0]);
    }
    throw new JsonGrammarError(`unexpected input at ${this.i}`);
  }

  object(depth: number): JObj {
    if (depth > MAX_DEPTH) throw new JsonGrammarError('nesting too deep');
    const out: JObj = new Map();
    this.i++; // {
    this.ws();
    if (this.s[this.i] === '}') {
      this.i++;
      return out;
    }
    for (;;) {
      this.ws();
      if (this.s[this.i] !== '"') throw new JsonGrammarError(`expected a key at ${this.i}`);
      const k = this.string();
      this.ws();
      if (this.s[this.i] !== ':') throw new JsonGrammarError(`expected ':' at ${this.i}`);
      this.i++;
      this.ws();
      out.set(k, this.value(depth)); // a duplicate key: the last one wins
      this.ws();
      const c = this.s[this.i];
      this.i++;
      if (c === '}') return out;
      if (c !== ',') throw new JsonGrammarError(`expected ',' or '}' at ${this.i - 1}`);
    }
  }

  array(depth: number): JVal[] {
    if (depth > MAX_DEPTH) throw new JsonGrammarError('nesting too deep');
    const out: JVal[] = [];
    this.i++; // [
    this.ws();
    if (this.s[this.i] === ']') {
      this.i++;
      return out;
    }
    for (;;) {
      this.ws();
      out.push(this.value(depth));
      this.ws();
      const c = this.s[this.i];
      this.i++;
      if (c === ']') return out;
      if (c !== ',') throw new JsonGrammarError(`expected ',' or ']' at ${this.i - 1}`);
    }
  }

  string(): string {
    const s = this.s;
    this.i++; // opening quote
    let out = '';
    let start = this.i;
    for (;;) {
      if (this.i >= s.length) throw new JsonGrammarError('unterminated string');
      const c = s.charCodeAt(this.i);
      if (c === 0x22) {
        out += s.slice(start, this.i);
        this.i++;
        return out.replace(LONE_SURROGATE, '\ufffd');
      }
      if (c < 0x20) throw new JsonGrammarError(`control character in string at ${this.i}`);
      if (c !== 0x5c) {
        this.i++;
        continue;
      }
      out += s.slice(start, this.i);
      const e = s[this.i + 1];
      switch (e) {
        case '"':
          out += '"';
          break;
        case '\\':
          out += '\\';
          break;
        case '/':
          out += '/';
          break;
        case 'b':
          out += '\b';
          break;
        case 'f':
          out += '\f';
          break;
        case 'n':
          out += '\n';
          break;
        case 'r':
          out += '\r';
          break;
        case 't':
          out += '\t';
          break;
        case 'u': {
          const hex = s.slice(this.i + 2, this.i + 6);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) throw new JsonGrammarError(`bad \\u escape at ${this.i}`);
          out += String.fromCharCode(parseInt(hex, 16));
          this.i += 4;
          break;
        }
        default:
          throw new JsonGrammarError(`bad escape at ${this.i}`);
      }
      this.i += 2;
      start = this.i;
    }
  }
}

// ---------------------------------------------------------------------------
// Canonical JSON: Python json.dumps(sort_keys=True, separators=(",", ":"),
// ensure_ascii=True), number lexemes kept.
// ---------------------------------------------------------------------------

function escapeString(s: string): string {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 0x22) out += '\\"';
    else if (c === 0x5c) out += '\\\\';
    else if (c === 0x08) out += '\\b';
    else if (c === 0x09) out += '\\t';
    else if (c === 0x0a) out += '\\n';
    else if (c === 0x0c) out += '\\f';
    else if (c === 0x0d) out += '\\r';
    else if (c < 0x20 || c >= 0x7f) out += '\\u' + c.toString(16).padStart(4, '0');
    else out += s[i];
  }
  return out + '"';
}

/** Code-point order (Python sorted() over str; Go's bytewise UTF-8 order). */
export function compareCodePoints(a: string, b: string): number {
  let i = 0;
  let j = 0;
  while (i < a.length && j < b.length) {
    const ca = a.codePointAt(i)!;
    const cb = b.codePointAt(j)!;
    if (ca !== cb) return ca - cb;
    i += ca > 0xffff ? 2 : 1;
    j += cb > 0xffff ? 2 : 1;
  }
  return (a.length - i) - (b.length - j);
}

export function canonical(v: JVal | readonly string[]): string {
  if (v === null) return 'null';
  if (v === true) return 'true';
  if (v === false) return 'false';
  if (typeof v === 'string') return escapeString(v);
  if (v instanceof JNum) return v.text;
  if (Array.isArray(v)) return '[' + v.map((x: JVal) => canonical(x)).join(',') + ']';
  if (v instanceof Map) {
    const keys = [...v.keys()].sort(compareCodePoints);
    return '{' + keys.map((k) => escapeString(k) + ':' + canonical(v.get(k) as JVal)).join(',') + '}';
  }
  throw new TypeError('canonical: unsupported value');
}

export function canonicalBytes(v: JVal): Uint8Array {
  // ensure_ascii output is pure ASCII: one byte per character.
  return Buffer.from(canonical(v), 'latin1');
}
