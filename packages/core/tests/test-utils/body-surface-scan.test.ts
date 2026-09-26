import { describe, it, expect } from 'vitest';
import { deflateSync } from 'node:zlib';

import { SecurityConfigSchema } from '../../src/models/config.js';
import { defaultLogger } from '../../src/models/logger.js';
import { scanRequestWithManager } from '../../src/utils.js';
import { createTestConfig, createMockRequest } from '../helpers.js';
import type { GuardRequest } from '../../src/protocols/request.js';
import type { SusPatternsManager } from '../../src/handlers/sus-patterns.js';

const MULTIPART_CONTENT_TYPE = 'multipart/form-data; boundary=B0';

/** Seeded uniform byte stream, mirroring the Python tests' _noise_bytes. */
function noiseBytes(seed: number, size: number): Uint8Array {
  let state = seed >>> 0;
  const out = new Uint8Array(size);
  for (let i = 0; i < size; i++) {
    state = (Math.imul(state, 1103515245) + 12345) >>> 0;
    out[i] = state & 0xff;
  }
  return out;
}

/** zlib level 9 over random bytes, mirroring _compressed_bytes: the result
 *  is binary-dense under the engine's string model. */
function compressedBytes(seed: number, size: number): Uint8Array {
  return deflateSync(noiseBytes(seed, size), { level: 9 });
}

function concatBytes(...chunks: Uint8Array[]): Uint8Array {
  const total = chunks.reduce((sum, c) => sum + c.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

function filePartBody(filename: string, content: Uint8Array, withContentType = true): Uint8Array {
  const head = new TextEncoder().encode(
    `--B0\r\nContent-Disposition: form-data; name="upload"; filename="${filename}"\r\n` +
    (withContentType ? 'Content-Type: application/octet-stream\r\n' : '') +
    '\r\n',
  );
  const tail = new TextEncoder().encode('\r\n--B0--\r\n');
  return concatBytes(head, content, tail);
}

function textPartBody(name: string, content: string): Uint8Array {
  return new TextEncoder().encode(
    `--B0\r\nContent-Disposition: form-data; name="${name}"\r\n\r\n${content}\r\n--B0--\r\n`,
  );
}

async function makeManager(configOverrides: Record<string, unknown> = {}): Promise<SusPatternsManager> {
  const { SusPatternsManager } = await import('../../src/handlers/sus-patterns.js');
  return new SusPatternsManager(createTestConfig(configOverrides), defaultLogger);
}

function bodyRequest(headers: Record<string, string>, body: Uint8Array): GuardRequest {
  return createMockRequest({
    method: 'POST',
    headers,
    body: async () => body,
  });
}

describe('body surface routing through the live engine', () => {
  it('detects sqli carried in a urlencoded form field', async () => {
    const manager = await makeManager();
    const [isThreat, info] = await scanRequestWithManager(
      manager,
      bodyRequest(
        { 'content-type': 'application/x-www-form-urlencoded' },
        new TextEncoder().encode('q=1+OR+1%3D1&note=benign'),
      ),
    );
    expect(isThreat).toBe(true);
    expect(info).toContain("Request body field 'q':");
  });

  it('detects an attack embedded in a JSON form field under the :embedded_json context', async () => {
    const manager = await makeManager();
    const [isThreat, info] = await scanRequestWithManager(
      manager,
      bodyRequest(
        { 'content-type': 'application/x-www-form-urlencoded' },
        new TextEncoder().encode('data=%7B%22a%22%3A%22%3Cscript%3Ealert%281%29%3C%2Fscript%3E%22%7D'),
      ),
    );
    expect(isThreat).toBe(true);
    expect(info).toContain("Request body field 'a':");
  });

  it('labels embedded JSON leaves with the :embedded_json context suffix', async () => {
    const manager = await makeManager();
    const seen: Array<{ context: string; content: string }> = [];
    const stub = {
      detect: async (content: string, _ip: string, context: string) => {
        seen.push({ context, content });
        return {
          isThreat: false, threatScore: 0, threats: [], executionTime: 0,
          timeouts: [], correlationId: null, originalLength: 1, processedLength: 1,
        };
      },
    } as unknown as SusPatternsManager;
    await scanRequestWithManager(
      stub,
      bodyRequest(
        { 'content-type': 'application/x-www-form-urlencoded' },
        new TextEncoder().encode('data={"a":"leaf"}'),
      ),
    );
    const leaf = seen.find((entry) => entry.content === 'leaf');
    expect(leaf?.context).toBe('request_body:form_field:embedded_json');
  });

  it('scans a plain multipart text part through the multipart context', async () => {
    const manager = await makeManager();
    const [isThreat, info] = await scanRequestWithManager(
      manager,
      bodyRequest({ 'content-type': MULTIPART_CONTENT_TYPE }, textPartBody('note', '<script>alert(1)</script>')),
    );
    expect(isThreat).toBe(true);
    expect(info).toContain("Request body field 'note':");
  });

  it('detects a malicious upload filename alongside harmless content', async () => {
    const manager = await makeManager();
    const [isThreat, info] = await scanRequestWithManager(
      manager,
      bodyRequest(
        { 'content-type': MULTIPART_CONTENT_TYPE },
        filePartBody('shell.php.jpg', new TextEncoder().encode('harmless-bytes')),
      ),
    );
    expect(isThreat).toBe(true);
    expect(info).toContain("Request body field 'upload':");
    expect(info).toContain('filename');
  });

  it('detects an attack in the multipart field NAME', async () => {
    const manager = await makeManager();
    const [isThreat, info] = await scanRequestWithManager(
      manager,
      bodyRequest(
        { 'content-type': MULTIPART_CONTENT_TYPE },
        new TextEncoder().encode(
          '--B0\r\nContent-Disposition: form-data; name="<img src=x onerror=alert(1)>"\r\n\r\nbenign\r\n--B0--\r\n',
        ),
      ),
    );
    expect(isThreat).toBe(true);
    expect(info).toContain('Multipart field name');
  });

  it('detects an intact script island inside a binary-dense file part', async () => {
    const manager = await makeManager();
    const payload = concatBytes(
      compressedBytes(12, 4096),
      new Uint8Array([0]),
      new TextEncoder().encode('<script>alert(1)</script>'),
      new Uint8Array([0]),
      compressedBytes(13, 4096),
    );
    const [isThreat] = await scanRequestWithManager(
      manager,
      bodyRequest({ 'content-type': MULTIPART_CONTENT_TYPE }, filePartBody('page.html.bin', payload)),
    );
    expect(isThreat).toBe(true);
  });

  it('does not detect a short smuggled fragment inside compressed upload bytes', async () => {
    const manager = await makeManager();
    const payload = concatBytes(
      compressedBytes(11, 4096),
      new Uint8Array([0]),
      new TextEncoder().encode('1 OR 1=1'),
      new Uint8Array([0]),
    );
    const [isThreat] = await scanRequestWithManager(
      manager,
      bodyRequest({ 'content-type': MULTIPART_CONTENT_TYPE }, filePartBody('installer.zip', payload)),
    );
    expect(isThreat).toBe(false);
  });

  it('does not let a pattern span two separate islands', async () => {
    const manager = await makeManager();
    const payload = concatBytes(
      compressedBytes(17, 4096),
      new Uint8Array([0]),
      new TextEncoder().encode('choose one: SELECT'),
      new Uint8Array([0]),
      new TextEncoder().encode('* FROM xYYYYYYYYYY'),
      new Uint8Array([0]),
    );
    const [isThreat] = await scanRequestWithManager(
      manager,
      bodyRequest({ 'content-type': MULTIPART_CONTENT_TYPE }, filePartBody('dump.bin', payload)),
    );
    expect(isThreat).toBe(false);
  });

  it('produces no noise from benign binary uploads', async () => {
    const manager = await makeManager();
    for (const [filename, content] of [
      ['photo.bin', noiseBytes(6, 4000)],
      ['blob.bin', new Uint8Array(4000).fill(0)],
    ] as const) {
      const [isThreat] = await scanRequestWithManager(
        manager,
        bodyRequest({ 'content-type': MULTIPART_CONTENT_TYPE }, filePartBody(filename, content)),
      );
      expect(isThreat, filename).toBe(false);
    }
  });

  it('honors a raised detectionBinaryMinRunLength end to end', async () => {
    const payload = concatBytes(
      compressedBytes(21, 4096),
      new Uint8Array([0]),
      new TextEncoder().encode('<script>alert(1)</script>'),
      new Uint8Array([0]),
    );
    const defaultManager = await makeManager();
    const [defaultThreat] = await scanRequestWithManager(
      defaultManager,
      bodyRequest({ 'content-type': MULTIPART_CONTENT_TYPE }, filePartBody('dump.bin', payload)),
    );
    expect(defaultThreat).toBe(true);

    const raisedManager = await makeManager({ detectionBinaryMinRunLength: 1024 });
    const [raisedThreat] = await scanRequestWithManager(
      raisedManager,
      bodyRequest({ 'content-type': MULTIPART_CONTENT_TYPE }, filePartBody('dump.bin', payload)),
    );
    expect(raisedThreat).toBe(false);
  });

  it('falls back to the whole-body blob scan when the boundary never matches', async () => {
    const manager = await makeManager();
    const raw = '--B0\r\nContent-Disposition: form-data; name="file"\r\n\r\n<script>alert(1)</script>\r\n--B0--\r\n';
    const [isThreat, info] = await scanRequestWithManager(
      manager,
      bodyRequest({ 'content-type': 'multipart/form-data; boundary=DOES-NOT-MATCH' }, new TextEncoder().encode(raw)),
    );
    expect(isThreat).toBe(true);
    expect(info).toContain('Request body:');
  });

  it('keeps the multipart scan inside the scan-value budget', async () => {
    const manager = await makeManager();
    const chunks: string[] = [];
    for (let i = 0; i < 200; i++) {
      chunks.push(
        `--B0\r\nContent-Disposition: form-data; name="field${i}"\r\n\r\nbenign\r\n`,
      );
    }
    chunks.push(
      '--B0\r\nContent-Disposition: form-data; name="evil"\r\n\r\n<img src=x onerror=alert(1)>\r\n--B0--\r\n',
    );
    const [isThreat] = await scanRequestWithManager(
      manager,
      bodyRequest({ 'content-type': MULTIPART_CONTENT_TYPE }, new TextEncoder().encode(chunks.join(''))),
    );
    expect(isThreat).toBe(false);

    const shortManager = await makeManager();
    const [shortThreat] = await scanRequestWithManager(
      shortManager,
      bodyRequest({ 'content-type': MULTIPART_CONTENT_TYPE }, textPartBody('evil', '<img src=x onerror=alert(1)>')),
    );
    expect(shortThreat).toBe(true);
  });
});

describe('recon gate and raw-view semantics for form fields', () => {
  it('does not flag the bare word default in a form field', async () => {
    const manager = await makeManager();
    const [isThreat] = await scanRequestWithManager(
      manager,
      bodyRequest(
        { 'content-type': 'application/x-www-form-urlencoded' },
        new TextEncoder().encode('page=default'),
      ),
    );
    expect(isThreat).toBe(false);
  });

  it('flags a separator-prefixed recon probe in a form field', async () => {
    const manager = await makeManager();
    const [isThreat] = await scanRequestWithManager(
      manager,
      bodyRequest(
        { 'content-type': 'application/x-www-form-urlencoded' },
        new TextEncoder().encode('page=/default'),
      ),
    );
    expect(isThreat).toBe(true);
  });

  /* The recon bare-word gate accepts a `\default` probe (the matched value
     starts with a backslash). The configured preprocessing pipeline folds the
     LDAP hex escape `\de` into `Þ` before the recon rows run, so detection
     rides on the raw-view recon membership (guard-core commit 81cf07f1): the
     recon rows join the signal-preserving raw view and the probe fires
     through the form-field scan. */
  it('flags a backslash-prefixed recon probe in a form field', async () => {
    const manager = await makeManager();
    const [isThreat] = await scanRequestWithManager(
      manager,
      bodyRequest(
        { 'content-type': 'application/x-www-form-urlencoded' },
        new TextEncoder().encode('page=%5Cdefault'),
      ),
    );
    expect(isThreat).toBe(true);
  });
});

describe('detectionBinaryMinRunLength config validation', () => {
  it('defaults to 16', () => {
    expect(SecurityConfigSchema.parse({}).detectionBinaryMinRunLength).toBe(16);
  });

  it('rejects values outside [4, 1024]', () => {
    expect(() => SecurityConfigSchema.parse({ detectionBinaryMinRunLength: 3 })).toThrow();
    expect(() => SecurityConfigSchema.parse({ detectionBinaryMinRunLength: 1025 })).toThrow();
  });

  it('accepts boundary values', () => {
    expect(SecurityConfigSchema.parse({ detectionBinaryMinRunLength: 4 }).detectionBinaryMinRunLength).toBe(4);
    expect(SecurityConfigSchema.parse({ detectionBinaryMinRunLength: 1024 }).detectionBinaryMinRunLength).toBe(1024);
  });

  it('is exposed by the manager for the scan routing', async () => {
    const manager = await makeManager({ detectionBinaryMinRunLength: 32 });
    expect(manager.detectionBinaryMinRunLength).toBe(32);
  });
});
