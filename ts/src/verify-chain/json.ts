// Strict JSON with number lexemes kept, and the canonical encoder the Lucairn
// producers sign with — parity corpus README § Input document and § Canonical
// JSON (Declade/dual-sandbox-architecture tools/parity-corpus/README.md).
//
// JSON.parse cannot be used: it turns numbers into doubles (2.0000000000000001
// becomes 2, 0.0 re-prints as 0, a 5,000-digit integer loses its digits), it
// lets a duplicate key win silently, and the recipe reads integer TOKENS and
// rebuilds signed bytes from the original number text. Objects are Maps so a
// key like "__proto__" is plain data.

/** A JSON number kept as its source lexeme. */
export class JNum {
  constructor(readonly text: string) {}
}

export type JVal = null | boolean | string | JNum | JVal[] | JObj;
export type JObj = Map<string, JVal>;

/**
 * Nesting bound (arrays/objects): the top-level value is level 1, every array
 * and object counts one, brackets inside strings do not count. The Python and
 * Go SDKs enforce the same bound; real certificates nest fewer than 10 levels.
 */
export const MAX_DEPTH = 256;

// Nesting bound of the LENIENT parser (parity test fixtures only): deep
// enough for a fixture that wraps an over-deep certificate, shallow enough
// that the recursive descent never exhausts the stack.
const LENIENT_MAX_DEPTH = 4096;

// A UTF-16 surrogate that is not part of a high + low pair.
const LONE_SURROGATE = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;

export class JsonGrammarError extends Error {}

const NUMBER_RE = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;
const HEX4 = /^[0-9a-fA-F]{4}$/;

/**
 * Parse exactly ONE RFC 8259 JSON value followed only by JSON whitespace
 * (space, tab, LF, CR) — the ONE strict document parser of the recipe:
 *
 * - bytes must be valid UTF-8; a byte-order mark is refused, not skipped;
 * - NaN / Infinity, a second value or stray trailing bytes are errors;
 * - at most {@link MAX_DEPTH} levels of nesting;
 * - every `\u` escape of a UTF-16 surrogate must be a high immediately
 *   followed by a low escape: an unpaired surrogate is refused, never
 *   replaced or kept (a string input carrying a raw unpaired surrogate is
 *   not valid UTF-8 text and is refused too);
 * - no object repeats a key, compared AFTER escape decoding (so `"a"` and
 *   `"a"` are the same key), code point for code point.
 *
 * Throws {@link JsonGrammarError}.
 */
export function parseDocument(input: string | Uint8Array): JVal {
  return parse(input, true);
}

/**
 * @internal Plain JSON with number lexemes kept, WITHOUT the verifier-input
 * rules (duplicate keys: last wins; surrogates kept; a generous depth bound).
 * For loading parity-corpus fixture files only, which wrap inputs that break
 * those rules on purpose. Never use it for a certificate or signed bytes.
 */
export function parseLenient(input: string | Uint8Array): JVal {
  return parse(input, false);
}

function parse(input: string | Uint8Array, strict: boolean): JVal {
  let s: string;
  if (typeof input === 'string') {
    if (strict && LONE_SURROGATE.test(input)) throw new JsonGrammarError('unpaired surrogate');
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
  const p = new Parser(s, strict);
  p.ws();
  const v = p.value(0);
  p.ws();
  if (p.i !== s.length) throw new JsonGrammarError(`trailing data at ${p.i}`);
  return v;
}

class Parser {
  i = 0;
  private readonly maxDepth: number;
  constructor(
    private readonly s: string,
    private readonly strict: boolean,
  ) {
    this.maxDepth = strict ? MAX_DEPTH : LENIENT_MAX_DEPTH;
  }

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
    if (depth > this.maxDepth) throw new JsonGrammarError('nesting too deep');
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
      // The key is escape-decoded and surrogate-checked by string() BEFORE
      // the duplicate comparison below (the pinned order).
      const k = this.string();
      if (this.strict && out.has(k)) throw new JsonGrammarError('duplicate key');
      this.ws();
      if (this.s[this.i] !== ':') throw new JsonGrammarError(`expected ':' at ${this.i}`);
      this.i++;
      this.ws();
      out.set(k, this.value(depth));
      this.ws();
      const c = this.s[this.i];
      this.i++;
      if (c === '}') return out;
      if (c !== ',') throw new JsonGrammarError(`expected ',' or '}' at ${this.i - 1}`);
    }
  }

  array(depth: number): JVal[] {
    if (depth > this.maxDepth) throw new JsonGrammarError('nesting too deep');
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
        if (this.strict && LONE_SURROGATE.test(out)) throw new JsonGrammarError('unpaired surrogate escape');
        return out;
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
          if (!HEX4.test(hex)) throw new JsonGrammarError(`bad \\u escape at ${this.i}`);
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

/**
 * Code-point order (Python sorted() over str; Go's bytewise UTF-8 order).
 * NOT JavaScript's default sort, which compares UTF-16 code units and puts a
 * supplementary-plane character before U+E000–U+FFFF.
 */
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
