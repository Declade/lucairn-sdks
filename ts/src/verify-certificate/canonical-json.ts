// Port of dual-sandbox-architecture/pkg/veil/canonical.go.
//
// TODO(proxy-sync): keep in lockstep with
//   dual-sandbox-architecture/pkg/veil/canonical.go
// Contract-drift-detector enforcement: any change to the Go source must land
// here in the same arc. The related gateway invariant
//   cert.request_id === cert.claims[0].request_id
// is enforced defensively in ./signable.ts — if the gateway ever breaks that
// invariant, both files need review.
//
// This is NOT RFC 8785 JCS. It is the witness's signing algorithm:
//   - recursive sorted keys at every map depth (Go sort.Strings, byte-wise
//     over UTF-8; see compareUtf8Bytes below — non-ASCII keys sort identically
//     to the witness)
//   - leaves through an ensure_ascii=True escaper that is byte-identical to the
//     witness signer (pkg/veil/canonical.go:encodePythonAsciiString): EVERY
//     UTF-16 code unit >= U+0080 becomes a lowercase \uXXXX escape (a
//     supplementary-plane rune is naturally two code units -> a surrogate pair
//     \uHHHH\uLLLL), and <, >, & are emitted LITERALLY (the witness does NOT
//     HTML-escape them). U+2028 / U+2029 are >= U+0080 so they escape too.
//   - integers-as-integers via the rawIntegerNumber branded type; naked JS
//     numbers throw at the boundary
// Output: zero whitespace, no trailing newline, UTF-8 bytes.
//
// Array-of-maps behaviour (N-new-5 probe in canonical-json-go-reference.hex):
// Go's marshalSorted does NOT recurse into arrays — arrays delegate to
// json.Marshal. json.Marshal's default behaviour on map[string]any IS to
// sort keys alphabetically (documented since Go 1.12), so Go and TS both
// produce identical bytes for arrays-of-maps even though the TS port
// reaches sorted-keys through explicit recursion. The probe in the
// golden-hex fixture locks this agreement in: if Go's behaviour ever
// changes (or the TS recursion is removed), the test fires.

const RAW_INT_BRAND = Symbol('RawIntegerNumber');

export interface RawIntegerNumber {
  readonly [RAW_INT_BRAND]: true;
  readonly value: string;
}

/**
 * Narrow helper: emit a JS integer as a raw JSON number (unquoted). Matches
 * Go's json.Marshal(int) output for integers. Rejects non-finite, non-integer,
 * and values outside the JS-safe-integer range.
 *
 * This is the only such helper the SDK exposes. Floats were intentionally
 * excluded — Go's json.Marshal float formatting diverges from JS's for many
 * values, and the Veil signed subset carries no floats.
 */
export function rawIntegerNumber(n: number): RawIntegerNumber {
  if (!Number.isSafeInteger(n)) {
    // Number.isSafeInteger implies Number.isInteger and rejects NaN/Infinity.
    throw new TypeError(`rawIntegerNumber: not a safe integer: ${n}`);
  }
  return { [RAW_INT_BRAND]: true, value: String(n) };
}

function isRawIntegerNumber(v: unknown): v is RawIntegerNumber {
  return (
    typeof v === 'object' &&
    v !== null &&
    (v as Record<symbol, unknown>)[RAW_INT_BRAND] === true
  );
}

export function canonicalJson(value: unknown): Uint8Array {
  const seen = new WeakSet<object>();
  const s = marshalSorted(value, seen);
  return new TextEncoder().encode(s);
}

// Lowercase-hex \uXXXX for a 16-bit code unit. The witness emits lowercase hex.
function u(codeUnit: number): string {
  return '\\u' + codeUnit.toString(16).padStart(4, '0');
}

/**
 * Serialize a string to a JSON string literal whose bytes are byte-identical
 * to Python's `json.dumps(s, ensure_ascii=True)` and the witness signer
 * (pkg/veil/canonical.go:encodePythonAsciiString).
 *
 * We iterate by UTF-16 code unit (the natural unit for a JS string), which
 * means a supplementary-plane rune is encountered as its two surrogate code
 * units and each is emitted as `\uHHHH` / `\uLLLL` — exactly the surrogate pair
 * the witness produces from utf16.EncodeRune. No HTML escaping: `<` `>` `&` are
 * emitted literally. U+2028 / U+2029 are >= U+0080 so they escape to \u2028 /
 * \u2029 through the general path. Char-class table (matches the witness):
 *
 *   U+0008 -> \b   U+0009 -> \t   U+000A -> \n   U+000C -> \f   U+000D -> \r
 *   other U+0000..U+001F -> \u00XX (lowercase)
 *   U+0022 (") -> \"      U+005C (\) -> \\
 *   U+0020..U+007E (incl < > &) -> literal (except the two above)
 *   U+007F (DEL) -> \u007f
 *   U+0080..U+FFFF (incl. surrogate code units) -> \uXXXX (lowercase)
 */
function stringifyLeaf(s: string): string {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    switch (c) {
      case 0x22: // "
        out += '\\"';
        break;
      case 0x5c: // backslash
        out += '\\\\';
        break;
      case 0x08:
        out += '\\b';
        break;
      case 0x09:
        out += '\\t';
        break;
      case 0x0a:
        out += '\\n';
        break;
      case 0x0c:
        out += '\\f';
        break;
      case 0x0d:
        out += '\\r';
        break;
      default:
        if (c < 0x20 || c === 0x7f || c >= 0x80) {
          // C0 controls (other than the short escapes above), DEL, and every
          // code unit >= U+0080 (incl. surrogate halves) -> lowercase \uXXXX.
          out += u(c);
        } else {
          // Printable ASCII U+0020..U+007E except " and \ — emit literally.
          // This deliberately includes <, >, & (the witness does NOT escape).
          out += s.charAt(i);
        }
    }
  }
  return out + '"';
}

// Module-level UTF-8 encoder reused by the key comparator (cheaper than
// allocating a fresh TextEncoder per comparison).
const KEY_UTF8_ENCODER = new TextEncoder();

/**
 * Compare two strings by their UTF-8 byte sequences (lexicographic, unsigned).
 * This is the ordering Go's encoding/json uses for map keys and the ordering
 * Python's canonical_json uses (`key=lambda k: k.encode("utf-8")`). JS's
 * default string `<` compares UTF-16 code units, which differs from UTF-8 byte
 * order for code points above U+FFFF. Using this comparator keeps the three
 * SDKs byte-identical for any key set, ASCII or not.
 */
function compareUtf8Bytes(a: string, b: string): number {
  if (a === b) return 0;
  const ab = KEY_UTF8_ENCODER.encode(a);
  const bb = KEY_UTF8_ENCODER.encode(b);
  const n = Math.min(ab.length, bb.length);
  for (let i = 0; i < n; i++) {
    if (ab[i] !== bb[i]) return ab[i] - bb[i];
  }
  return ab.length - bb.length;
}

function marshalSorted(v: unknown, seen: WeakSet<object>): string {
  if (isRawIntegerNumber(v)) return v.value;
  if (v === null) return 'null';
  if (typeof v === 'boolean') return v ? 'true' : 'false';
  if (typeof v === 'number') {
    // Defensive: refuse raw JS numbers at the canonical-JSON boundary. All
    // integer leaves must use rawIntegerNumber; all strings stay strings.
    // This prevents accidental float-encoding divergence between JS and Go.
    throw new TypeError(
      `canonicalJson: raw number ${v} — wrap with rawIntegerNumber() for integers, or pass as string`,
    );
  }
  if (typeof v === 'string') return stringifyLeaf(v);
  if (Array.isArray(v)) {
    if (seen.has(v)) {
      throw new TypeError('canonicalJson: circular reference in array');
    }
    seen.add(v);
    const parts = v.map((item) => marshalSorted(item, seen));
    seen.delete(v);
    return `[${parts.join(',')}]`;
  }
  if (typeof v === 'object') {
    if (seen.has(v as object)) {
      throw new TypeError('canonicalJson: circular reference in object');
    }
    seen.add(v as object);
    const obj = v as Record<string, unknown>;
    // Bytewise UTF-8 key sort — matches Go's encoding/json (which orders map
    // keys by their raw string bytes, i.e. UTF-8) and Python's
    // `sorted(keys, key=lambda k: k.encode("utf-8"))`. JS's default
    // `Array.prototype.sort()` compares UTF-16 code units, which diverges from
    // UTF-8 byte order for characters above the BMP (e.g. emoji, whose
    // surrogate-pair code units sort before BMP chars like U+E000–U+FFFF while
    // their UTF-8 bytes sort after). The Veil signable key set is ASCII-only so
    // this is byte-equivalent on every real cert; the explicit UTF-8 sort keeps
    // all three SDKs in exact parity if a non-ASCII signed key is ever added.
    const keys = Object.keys(obj).sort(compareUtf8Bytes);
    const parts = keys.map(
      (k) => `${stringifyLeaf(k)}:${marshalSorted(obj[k], seen)}`,
    );
    seen.delete(v as object);
    return `{${parts.join(',')}}`;
  }
  throw new TypeError(`canonicalJson: unsupported value type ${typeof v}`);
}
