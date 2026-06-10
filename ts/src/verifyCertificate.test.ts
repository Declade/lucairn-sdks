import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { generateKeyPairSync, sign, type JsonWebKey } from 'node:crypto';
import { normalizeEd25519PublicKey } from './verify-certificate/keys.js';
import { verifyEd25519 } from './verify-certificate/signature.js';
import { verifyCertificate } from './verify-certificate/index.js';
import { deriveWitnessSignedBytes } from './verify-certificate/signable.js';
import { parseCertificate } from './verify-certificate/parse.js';
import { LucairnCertificateError } from './errors.js';
import type { VeilCertificate, VerifyCertificateKeys } from './types.js';

const fixturesDir = join(__dirname, 'verify-certificate', '__fixtures__');

function loadFixture<T = VeilCertificate>(name: string): T {
  return JSON.parse(readFileSync(join(fixturesDir, name), 'utf8')) as T;
}

interface WitnessKeypairFixture {
  publicKey: string; // base64 raw 32B
  privateKeyJwk: JsonWebKey;
}

function keysAll(): VerifyCertificateKeys {
  const kp = loadFixture<WitnessKeypairFixture>('witness-keypair.json');
  return {
    witnessKeyId: 'witness_v1',
    witnessPublicKey: kp.publicKey,
  };
}

// Extract the raw 32-byte Ed25519 public key from a node:crypto KeyObject.
// Node's Ed25519 public-key JWK format carries `x` as base64url of the raw
// 32 bytes.
function rawPubFromKeyObject(pk: {
  export(options: { format: 'jwk' }): JsonWebKey;
}): Uint8Array {
  const jwk = pk.export({ format: 'jwk' });
  if (typeof jwk.x !== 'string') {
    throw new Error('expected Ed25519 JWK with string x');
  }
  const b64 = jwk.x.replace(/-/g, '+').replace(/_/g, '/');
  return new Uint8Array(Buffer.from(b64, 'base64'));
}

describe('normalizeEd25519PublicKey', () => {
  it('passes Uint8Array of length 32 through', () => {
    const key = new Uint8Array(32).fill(0xaa);
    expect(normalizeEd25519PublicKey(key)).toEqual(key);
  });

  it('decodes base64 string into 32 bytes', () => {
    const bytes = new Uint8Array(32).fill(0xbb);
    const b64 = Buffer.from(bytes).toString('base64');
    expect(normalizeEd25519PublicKey(b64)).toEqual(bytes);
  });

  it('throws TypeError for wrong length (too short)', () => {
    expect(() => normalizeEd25519PublicKey(new Uint8Array(16))).toThrow(TypeError);
  });

  it('throws TypeError for wrong length (too long)', () => {
    expect(() => normalizeEd25519PublicKey(new Uint8Array(64))).toThrow(TypeError);
  });

  it('throws TypeError for non-string non-bytes input', () => {
    expect(() => normalizeEd25519PublicKey(42 as unknown as string)).toThrow(TypeError);
    expect(() => normalizeEd25519PublicKey(null as unknown as string)).toThrow(TypeError);
  });
});

describe('verifyEd25519', () => {
  it('verifies a signature produced by node:crypto sign() over the same message', () => {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const message = new TextEncoder().encode('the quick brown fox');
    const signature = sign(null, Buffer.from(message), privateKey);
    const raw = rawPubFromKeyObject(publicKey);
    expect(verifyEd25519(message, new Uint8Array(signature), raw)).toBe(true);
  });

  it('returns false for tampered signature', () => {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const message = new TextEncoder().encode('the quick brown fox');
    const sig = sign(null, Buffer.from(message), privateKey);
    sig[0] ^= 0x01; // flip one bit
    const raw = rawPubFromKeyObject(publicKey);
    expect(verifyEd25519(message, new Uint8Array(sig), raw)).toBe(false);
  });

  it('returns false for a message modified after signing', () => {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const original = new TextEncoder().encode('the quick brown fox');
    const sig = sign(null, Buffer.from(original), privateKey);
    const tampered = new TextEncoder().encode('the quick brown foz');
    const raw = rawPubFromKeyObject(publicKey);
    expect(verifyEd25519(tampered, new Uint8Array(sig), raw)).toBe(false);
  });

  it('accepts the public key as a base64 string', () => {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const message = new TextEncoder().encode('hello');
    const signature = sign(null, Buffer.from(message), privateKey);
    const raw = rawPubFromKeyObject(publicKey);
    const b64 = Buffer.from(raw).toString('base64');
    expect(verifyEd25519(message, new Uint8Array(signature), b64)).toBe(true);
  });

  it('throws TypeError when the public key input is not a valid Ed25519 key', () => {
    const message = new TextEncoder().encode('hello');
    const sig = new Uint8Array(64);
    expect(() => verifyEd25519(message, sig, new Uint8Array(16))).toThrow(TypeError);
  });
});

describe('cert fixtures loadable', () => {
  it('cert-valid-anchored.json matches expected shape', () => {
    const cert = loadFixture('cert-valid-anchored.json');
    expect(cert.protocol_version).toBe(2);
    expect(cert.anchor_status?.status).toBe('ANCHOR_STATUS_ANCHORED');
    expect(cert.verification.overall_verdict).toBe('VERDICT_VERIFIED');
    expect(cert.witness_signature).toBeTruthy();
    expect(cert.witness_key_id).toBe('witness_v1');
  });

  // B2 — lock in the protojson-UTC assumption. If the gateway ever ships
  // a `+00:00` suffix instead of `Z`, this fails loudly so signable
  // reconstruction doesn't silently produce `invalid_signature` on valid
  // certs.
  it('cert.issued_at terminates in Z (protojson UTC form)', () => {
    expect(loadFixture('cert-valid-anchored.json').issued_at).toMatch(/Z$/);
  });

  it('pending + failed + tampered variants parse as JSON', () => {
    expect(loadFixture('cert-valid-pending.json').anchor_status?.status).toBe(
      'ANCHOR_STATUS_PENDING',
    );
    expect(loadFixture('cert-valid-failed.json').anchor_status?.status).toBe(
      'ANCHOR_STATUS_FAILED',
    );
    expect(loadFixture('cert-tampered-payload.json').claims[0]?.claim_id).toMatch(
      /TAMPERED$/,
    );
  });

  it('no-signature + whitespace-signature variants have empty/whitespace witness_signature', () => {
    expect(loadFixture('cert-no-signature.json').witness_signature).toBe('');
    expect(loadFixture('cert-whitespace-signature.json').witness_signature).toMatch(
      /^\s+$/,
    );
  });

  it('protocol-version-mismatch variant carries non-2 protocol_version', () => {
    expect(loadFixture('cert-protocol-version-mismatch.json').protocol_version).toBe(
      999,
    );
  });
});

describe('verifyCertificate — failure reasons', () => {
  it('throws malformed when cert is not a JSON object', async () => {
    await expect(
      verifyCertificate(null as unknown as VeilCertificate, keysAll()),
    ).rejects.toMatchObject({ reason: 'malformed' });
    await expect(
      verifyCertificate('string' as unknown as VeilCertificate, keysAll()),
    ).rejects.toMatchObject({ reason: 'malformed' });
    await expect(
      verifyCertificate([] as unknown as VeilCertificate, keysAll()),
    ).rejects.toMatchObject({ reason: 'malformed' });
  });

  it('throws malformed when required fields are missing', async () => {
    await expect(
      verifyCertificate(loadFixture('cert-malformed-truncated.json'), keysAll()),
    ).rejects.toMatchObject({ reason: 'malformed' });
  });

  it('throws malformed when cert.request_id != cert.claims[0].request_id (gateway invariant)', async () => {
    const cert = loadFixture('cert-valid-anchored.json');
    cert.request_id = 'req_different_from_claims';
    await expect(verifyCertificate(cert, keysAll())).rejects.toMatchObject({
      reason: 'malformed',
    });
  });

  it('throws malformed on unknown overall_verdict enum literal', async () => {
    const cert = loadFixture('cert-valid-anchored.json');
    (cert.verification as { overall_verdict: string }).overall_verdict =
      'VERDICT_FUTURE_VALUE';
    await expect(verifyCertificate(cert, keysAll())).rejects.toMatchObject({
      reason: 'malformed',
    });
  });

  it('throws unsupported_protocol_version for non-2 protocol_version', async () => {
    await expect(
      verifyCertificate(loadFixture('cert-protocol-version-mismatch.json'), keysAll()),
    ).rejects.toMatchObject({ reason: 'unsupported_protocol_version' });
  });

  it('throws witness_mismatch when keys.witnessKeyId differs from cert.witness_key_id', async () => {
    await expect(
      verifyCertificate(loadFixture('cert-valid-anchored.json'), {
        ...keysAll(),
        witnessKeyId: 'different-label',
      }),
    ).rejects.toMatchObject({ reason: 'witness_mismatch' });
  });

  it('throws witness_signature_missing when witness_signature is empty', async () => {
    await expect(
      verifyCertificate(loadFixture('cert-no-signature.json'), keysAll()),
    ).rejects.toMatchObject({ reason: 'witness_signature_missing' });
  });

  it('throws witness_signature_missing when witness_signature is whitespace-only', async () => {
    await expect(
      verifyCertificate(loadFixture('cert-whitespace-signature.json'), keysAll()),
    ).rejects.toMatchObject({ reason: 'witness_signature_missing' });
  });

  it('throws invalid_signature when cert payload is tampered after signing', async () => {
    await expect(
      verifyCertificate(loadFixture('cert-tampered-payload.json'), keysAll()),
    ).rejects.toMatchObject({ reason: 'invalid_signature' });
  });

  it('throws invalid_signature with preserved TypeError on malformed witnessPublicKey', async () => {
    try {
      await verifyCertificate(loadFixture('cert-valid-anchored.json'), {
        witnessKeyId: 'witness_v1',
        witnessPublicKey: new Uint8Array(16), // wrong length
      });
      throw new Error('expected to throw');
    } catch (err) {
      expect(err).toBeInstanceOf(LucairnCertificateError);
      const typed = err as LucairnCertificateError;
      expect(typed.reason).toBe('invalid_signature');
      expect(typed.cause).toBeInstanceOf(TypeError);
    }
  });
});

describe('verifyCertificate — happy paths', () => {
  it('returns VerifyCertificateResult on valid ANCHORED cert, including ISO timestamp', async () => {
    const cert = loadFixture('cert-valid-anchored.json');
    const result = await verifyCertificate(cert, keysAll());
    expect(result).toEqual({
      certificateId: cert.certificate_id,
      requestId: cert.request_id,
      witnessKeyId: 'witness_v1',
      witnessAssertedIssuedAt: new Date(cert.issued_at),
      witnessAssertedIssuedAtIso: cert.issued_at,
      anchorStatus: 'ANCHOR_STATUS_ANCHORED',
      overallVerdict: 'VERDICT_VERIFIED',
      signableVersion: 'v2', // no signable_protocol_version_emitted on this fixture → v2 path
      v3SignatureStripped: false, // always false on the success path (TOB-SDK-TS-01)
    });
  });

  it('passes anchor_status PENDING through without gating verification', async () => {
    // Same signed payload — anchor_status is NOT in the signed subset.
    const result = await verifyCertificate(loadFixture('cert-valid-pending.json'), keysAll());
    expect(result.anchorStatus).toBe('ANCHOR_STATUS_PENDING');
  });

  it('passes anchor_status FAILED through without throwing (deferred to 2b-cert-strong)', async () => {
    const result = await verifyCertificate(loadFixture('cert-valid-failed.json'), keysAll());
    expect(result.anchorStatus).toBe('ANCHOR_STATUS_FAILED');
  });
});

// BYOK_EXEMPT — sister of dual-sandbox-architecture's
// ISOLATION_PROBE_BYOK_EXEMPT proto enum + VerificationResult.byok_exempt
// (proto field 9). The cert reaches the SDK with both new fields populated;
// the SDK must parse them, surface them on the typed cert, and verify the
// witness signature unchanged — because the witness signable map is still
// the same 7-key set (byok_exempt and the new probe enum are NOT in it).
describe('verifyCertificate — BYOK_EXEMPT', () => {
  it('parses and verifies a BYOK_EXEMPT cert as VERDICT_VERIFIED', async () => {
    const cert = loadFixture('cert-byok-exempt.json');
    expect(cert.verification.byok_exempt).toBe(true);
    expect(cert.verification.overall_verdict).toBe('VERDICT_VERIFIED');
    expect(cert.claims[2]?.inference?.isolation_probe).toBe(
      'ISOLATION_PROBE_BYOK_EXEMPT',
    );
    const result = await verifyCertificate(cert, keysAll());
    expect(result.overallVerdict).toBe('VERDICT_VERIFIED');
    expect(result.certificateId).toBe(cert.certificate_id);
    expect(result.requestId).toBe(cert.request_id);
    expect(result.anchorStatus).toBe('ANCHOR_STATUS_ANCHORED');
  });

  it('byok_exempt absent from older cert fixture defaults to undefined (backward compat)', async () => {
    // Older certs (pre-byok-exempt gateway) do not carry the field. The
    // optional field on VeilVerificationResult means the parsed object
    // simply has no `byok_exempt` key — not `false`, not a parse error.
    //
    // DRIFT-002 — also exercise the full verifyCertificate path so a future
    // signable-derivation regression on older-shape certs (e.g., accidentally
    // promoting `byok_exempt` into the signable map) gets caught at the
    // byte-identity layer, not just at the structural-parse layer. The witness
    // signable is the same 7-key set whether or not `byok_exempt` is present
    // on the wire, so the older fixture signature must still verify.
    const cert = loadFixture('cert-valid-anchored.json');
    expect(cert.verification.byok_exempt).toBeUndefined();

    const result = await verifyCertificate(cert, keysAll());
    expect(result.overallVerdict).toBe('VERDICT_VERIFIED');
    expect(result.anchorStatus).toBe('ANCHOR_STATUS_ANCHORED');
  });
});

describe('verifyCertificate — ordering + error shape', () => {
  it('stops at malformed before protocol-version / witness-id checks', async () => {
    await expect(
      verifyCertificate(loadFixture('cert-malformed-truncated.json'), {
        witnessKeyId: 'any',
        witnessPublicKey: new Uint8Array(32),
      }),
    ).rejects.toMatchObject({ reason: 'malformed' });
  });

  // C5 — full ordering lock-in. Cert is BOTH malformed (claims is a string
  // not an array) AND has wrong protocol_version. Parse must fire first so
  // verify returns `malformed`, not `unsupported_protocol_version`.
  it('stops at malformed before unsupported_protocol_version (parse wins)', async () => {
    await expect(
      verifyCertificate(
        loadFixture('cert-malformed-plus-bad-version.json'),
        keysAll(),
      ),
    ).rejects.toMatchObject({ reason: 'malformed' });
  });

  it('stops at unsupported_protocol_version before witness-id check', async () => {
    await expect(
      verifyCertificate(loadFixture('cert-protocol-version-mismatch.json'), {
        ...keysAll(),
        witnessKeyId: 'wrong-label',
      }),
    ).rejects.toMatchObject({ reason: 'unsupported_protocol_version' });
  });

  it('LucairnCertificateError.certificateId is populated when cert parses', async () => {
    try {
      await verifyCertificate(loadFixture('cert-tampered-payload.json'), keysAll());
      throw new Error('expected to throw');
    } catch (err) {
      expect(err).toBeInstanceOf(LucairnCertificateError);
      const typed = err as LucairnCertificateError;
      expect(typed.reason).toBe('invalid_signature');
      expect(typed.certificateId).toBe(
        loadFixture('cert-tampered-payload.json').certificate_id,
      );
    }
  });

  it('LucairnCertificateError.certificateId is undefined when cert fails structural parse', async () => {
    try {
      await verifyCertificate('garbage' as unknown as VeilCertificate, keysAll());
      throw new Error('expected to throw');
    } catch (err) {
      expect(err).toBeInstanceOf(LucairnCertificateError);
      expect((err as LucairnCertificateError).certificateId).toBeUndefined();
    }
  });
});

describe('verifyCertificate — Go-oracle cross-check (end-to-end)', () => {
  // This is the authoritative "does the TS port agree with Go end-to-end"
  // test. The fixture (cert-go-signed-reference.json) is produced by the
  // Go oracle at
  //   dual-sandbox-architecture/services/veil-witness/internal/testoracle/
  //   gen-cert-oracle.go
  // which invokes the real assembler.Assemble pipeline (including
  // pkg/veil.CanonicalJSON + Ed25519 signing) with fixed clock + fixed
  // ID generator. Any drift between the Go assembler's signing path and
  // the TS deriveWitnessSignedBytes path fails this test immediately —
  // which is how we caught the earlier integer-vs-string encoding bug
  // for overall_verdict.
  //
  // If this test ever fails after a gateway change, re-run the oracle
  // per the regen instructions at
  //   dual-sandbox-architecture/services/veil-witness/internal/testoracle/
  //   README.md
  // and investigate: the Go side changed its signable-field encoding and
  // the TS port must match. Do NOT paper over by regenerating both.
  it('TS verifyCertificate accepts a Go-oracle-signed cert', async () => {
    const goCert = loadFixture('cert-go-signed-reference.json');
    const oracleKp = JSON.parse(
      readFileSync(join(fixturesDir, 'test-witness-keypair.json'), 'utf8'),
    ) as { publicKey: string };
    const result = await verifyCertificate(goCert, {
      witnessKeyId: 'witness_v1',
      witnessPublicKey: oracleKp.publicKey,
    });
    expect(result.certificateId).toBe('veil_oracle_0000000000000001');
    expect(result.requestId).toBe('req_oracle_0000000000000001');
    expect(result.witnessKeyId).toBe('witness_v1');
    expect(result.overallVerdict).toBe('VERDICT_VERIFIED');
    expect(result.anchorStatus).toBe('ANCHOR_STATUS_ANCHORED');
  });
});

describe('verifyCertificate — bug-hunter C4/C5 gap fills', () => {
  it('throws malformed on cert with empty claims array (C4 — empty-claims path)', async () => {
    const cert = loadFixture('cert-valid-anchored.json');
    cert.claims = [];
    await expect(verifyCertificate(cert, keysAll())).rejects.toMatchObject({
      reason: 'malformed',
    });
  });

  it('throws malformed on cert with empty-string overall_verdict (C5)', async () => {
    const cert = loadFixture('cert-valid-anchored.json');
    (cert.verification as { overall_verdict: string }).overall_verdict = '';
    await expect(verifyCertificate(cert, keysAll())).rejects.toMatchObject({
      reason: 'malformed',
    });
  });

  it('throws malformed on cert with claim element whose claim_id is not a string', async () => {
    const cert = loadFixture('cert-valid-anchored.json');
    // Matches bug-hunter C1's cascade path — without the bounded claim_id
    // check in signable, this would surface as a raw canonical-json TypeError.
    (cert.claims[0] as { claim_id: unknown }).claim_id = 42;
    await expect(verifyCertificate(cert, keysAll())).rejects.toMatchObject({
      reason: 'malformed',
    });
  });

  it('throws malformed on cert with null claim element (C1 cascade)', async () => {
    const cert = loadFixture('cert-valid-anchored.json');
    // Push a null after the first valid claim. C2 (request_id match on
    // claims[0]) still passes; the C1 per-element validation in signable
    // must catch claims[1] = null before canonicalJson gets hold of it.
    (cert.claims as unknown as Array<unknown>).push(null);
    await expect(verifyCertificate(cert, keysAll())).rejects.toMatchObject({
      reason: 'malformed',
    });
  });

  it('throws TypeError (not LucairnCertificateError) on null keys argument', async () => {
    await expect(
      verifyCertificate(
        loadFixture('cert-valid-anchored.json'),
        null as unknown as VerifyCertificateKeys,
      ),
    ).rejects.toThrow(TypeError);
  });

  it('throws malformed with a semantically-correct message on empty-claims cert (N2)', async () => {
    const cert = loadFixture('cert-valid-anchored.json');
    cert.claims = [];
    try {
      await verifyCertificate(cert, keysAll());
      throw new Error('expected to throw');
    } catch (err) {
      expect(err).toBeInstanceOf(LucairnCertificateError);
      const typed = err as LucairnCertificateError;
      expect(typed.reason).toBe('malformed');
      expect(typed.message).toMatch(/claims is empty/);
    }
  });

  it('throws malformed on sparse-array hole inside claims (N1)', async () => {
    const cert = loadFixture('cert-valid-anchored.json');
    // Construct a sparse array: one valid claim at [0], hole at [1], valid
    // claim at [2]. Array.prototype.map would skip the hole; the new
    // for-loop with `i in cert.claims` catches it.
    const sparse: unknown[] = [cert.claims[0]];
    sparse[2] = cert.claims[1];
    (cert as unknown as { claims: unknown[] }).claims = sparse;
    await expect(verifyCertificate(cert, keysAll())).rejects.toMatchObject({
      reason: 'malformed',
    });
  });

  it('resists Object.prototype pollution via overall_verdict="__proto__"', async () => {
    // Without Object.hasOwn (or a null-prototype lookup table),
    // VERDICT_FULL_TO_SHORT['__proto__'] would resolve to Object.prototype,
    // bypass the membership check, and leak a raw TypeError from a
    // downstream string validation. With the fix, this is caught as
    // `malformed` like any other unknown enum literal.
    const cert = loadFixture('cert-valid-anchored.json');
    (cert.verification as { overall_verdict: string }).overall_verdict = '__proto__';
    await expect(verifyCertificate(cert, keysAll())).rejects.toMatchObject({
      reason: 'malformed',
    });
  });
});

describe('Lucairn#verifyCertificate client delegation', () => {
  // Client-level smoke test — ensures the public method on Lucairn
  // delegates to the standalone verify function without drift.
  it('delegates to verify-certificate/index and returns the same result shape', async () => {
    // Avoid cross-file import cycles by importing inline.
    const { Lucairn } = await import('./client.js');
    const client = new Lucairn({ apiKey: 'dsa_' + '0'.repeat(32) });
    const cert = loadFixture('cert-valid-anchored.json');
    const result = await client.verifyCertificate(cert, keysAll());
    expect(result.witnessKeyId).toBe('witness_v1');
    expect(result.anchorStatus).toBe('ANCHOR_STATUS_ANCHORED');
    expect(result.overallVerdict).toBe('VERDICT_VERIFIED');
  });
});

// ---------------------------------------------------------------------------
// Live-throw alias regression (bug-hunter M2). The static identity test in
// errors.test.ts at the `TheVeil* === Lucairn*` constructor level only proves
// the legacy aliases are correctly re-exported. It does NOT prove that an
// error THROWN from inside verify-certificate/ at runtime is catchable as
// either name. After Fix 1 swapped the verify-certificate/ throws to use the
// canonical LucairnCertificateError name, this guard makes the dual-name
// catchability invariant explicit so a future migration that drops one alias
// fails this test loudly rather than silently breaking pre-Stage-3 callers.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// TOB-001 — Signable freeze test. The 7-key witness signable map is a
// hard-locked W2A invariant: any change to its shape, key order
// (canonical-JSON sorts alphabetically so this is automatic), or per-field
// encoding breaks every external verifier in the wild. Locking the canonical
// bytes against a Go-reference hex fixture catches regressions at the
// byte-identity layer rather than at the higher signature-verification layer
// (which would surface as `invalid_signature` on an otherwise-valid cert and
// give no signal about which field encoding drifted).
//
// The hex was produced by running `deriveWitnessSignedBytes` over
// `cert-go-signed-reference.json` (which is itself produced by the Go
// assembler oracle — see verifyCertificate.test.ts:355-389) and is the
// authoritative pinned canonical form. If this test fails after a deliberate
// signable-shape change, regenerate BOTH the Go-side and SDK-side fixtures
// per the steps documented at
//   dual-sandbox-architecture/services/veil-witness/internal/testoracle/README.md
// — never paper over by regenerating just this hex.
// ---------------------------------------------------------------------------
describe('deriveWitnessSignedBytes — signable freeze (TOB-001)', () => {
  it('produces byte-identical canonical bytes against the Go-reference cert fixture', () => {
    const expectedHex = readFileSync(
      join(fixturesDir, 'signable-go-reference.hex'),
      'utf8',
    ).trim();
    const goCert = parseCertificate(loadFixture('cert-go-signed-reference.json'));
    const bytes = deriveWitnessSignedBytes(goCert);
    const actualHex = Buffer.from(bytes).toString('hex');
    expect(actualHex).toBe(expectedHex);
  });

  it('signable contains exactly the 7 keys (sorted) — no byok_exempt, no client_id', () => {
    // Defense-in-depth: a hex equality assertion above already pins the
    // exact bytes, but a structural assertion at the JSON layer is easier
    // to read in the failure message if a future contributor adds a key.
    const goCert = parseCertificate(loadFixture('cert-go-signed-reference.json'));
    const bytes = deriveWitnessSignedBytes(goCert);
    const decoded = JSON.parse(new TextDecoder().decode(bytes)) as Record<
      string,
      unknown
    >;
    expect(Object.keys(decoded).sort()).toEqual([
      'certificate_id',
      'claim_ids',
      'issued_at',
      'overall_verdict',
      'protocol_version',
      'request_id',
      'witness_key_id',
    ]);
    // byok_exempt MUST NOT leak into the signable — tamper-evidence is
    // INDIRECT via the bridge claim's bridge-signed canonical_payload.
    expect(decoded).not.toHaveProperty('byok_exempt');
    expect(decoded).not.toHaveProperty('client_id');
  });
});

describe('verifyCertificate alias regression — live throws are catchable as both names', () => {
  it('a malformed-input rejection satisfies instanceof for both LucairnCertificateError and TheVeilCertificateError', async () => {
    const { TheVeilCertificateError } = await import('./errors.js');
    let caught: unknown;
    try {
      await verifyCertificate(null as unknown as VeilCertificate, keysAll());
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(LucairnCertificateError);
    expect(caught).toBeInstanceOf(TheVeilCertificateError);
    // Sanity: the constructor identity invariant the static test asserts —
    // re-asserted here at the throw site so the regression boundary is
    // colocated with the throw path.
    expect(LucairnCertificateError).toBe(TheVeilCertificateError);
  });
});
