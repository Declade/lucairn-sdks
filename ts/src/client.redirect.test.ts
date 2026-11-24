/**
 * Transport rules for key-carrying requests (security fix stream T-1474,
 * slice F16; level-2 entry 11 and low 12):
 *   - the client never follows a redirect, so the API key is never sent to
 *     the address a Location header names;
 *   - plain `http://` base addresses are refused except for this machine.
 * Synthetic key, two local stand-in servers only.
 */

import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createServer, type IncomingHttpHeaders, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { server as msw } from './test-server.js';
import { Lucairn } from './client.js';
import { LucairnConfigError, LucairnHttpError } from './errors.js';

const SYNTHETIC_KEY = `dsa_${'0'.repeat(32)}`;

function listen(handler: Parameters<typeof createServer>[1]): Promise<Server> {
  return new Promise((resolve) => {
    const s = createServer(handler);
    s.listen(0, '127.0.0.1', () => resolve(s));
  });
}
const port = (s: Server) => (s.address() as AddressInfo).port;

describe('Lucairn client — redirects are never followed (F16)', () => {
  // Real sockets for this block: the shared request mock steps aside (it
  // would not show what the network stack does with a Location header).
  beforeAll(() => msw.close());
  afterAll(() => msw.listen({ onUnhandledRequest: 'error' }));
  let first: Server;
  let second: Server;
  const secondSaw: IncomingHttpHeaders[] = [];

  beforeEach(async () => {
    secondSaw.length = 0;
    second = await listen((req, res) => {
      secondSaw.push(req.headers);
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('{}');
    });
    first = await listen((_req, res) => {
      res.writeHead(307, { location: `http://127.0.0.1:${port(second)}/v1/messages` });
      res.end();
    });
  });

  afterEach(async () => {
    for (const s of [first, second]) {
      s.closeAllConnections();
      await new Promise((r) => s.close(r));
    }
  });

  it('a 307 to another local port is an error and the key never reaches the second address', async () => {
    const client = new Lucairn({ apiKey: SYNTHETIC_KEY, baseUrl: `http://127.0.0.1:${port(first)}` });
    const err = await client
      .getCertificate('req_f16_redirect')
      .then(() => null, (e: unknown) => e);
    expect(err).toBeInstanceOf(LucairnHttpError);
    expect((err as LucairnHttpError).status).toBe(307);
    expect(secondSaw).toHaveLength(0);
  });
});

describe('Lucairn constructor — plain http only for loopback (F16)', () => {
  for (const ok of [
    'http://localhost:8080',
    'http://LOCALHOST:8080',
    'HTTP://127.0.0.1:8080',
    'http://127.10.20.30',
    'http://[::1]:8080',
    'https://gateway.example.com',
  ]) {
    it(`accepts ${ok}`, () => {
      expect(() => new Lucairn({ apiKey: SYNTHETIC_KEY, baseUrl: ok })).not.toThrow();
    });
  }
  for (const bad of [
    'http://gateway.example.com',
    'HTTP://gateway.example.com',
    'http://localhost.evil.example',
    'http://localhost@evil.example',
    'http://127.0.0.1@evil.example',
    'http://127.0.0.1.evil.example',
    'http://evil.example#@localhost',
    'http://128.0.0.1',
    'http://[::ffff:127.0.0.1]',
  ]) {
    it(`refuses ${bad}`, () => {
      expect(() => new Lucairn({ apiKey: SYNTHETIC_KEY, baseUrl: bad })).toThrow(LucairnConfigError);
    });
  }
});
