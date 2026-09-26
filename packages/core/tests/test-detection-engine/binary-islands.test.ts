import { describe, it, expect } from 'vitest';

import { extractBinaryIslands, valueIsBinaryLike } from '../../src/detection-engine/binary-islands.js';
import {
  multipartPartEntries,
  parseFormPairs,
  parseMediaTypeParams,
  parseMultipartParts,
} from '../../src/detection-engine/body-form-scan.js';

/** Rebuilds the exact code points a latin-1 decode produces, the TS
 *  equivalent of the Go tests' latin1Decoded helper: the lossy UTF-8 decoder
 *  of the request boundary collapses invalid byte runs into U+FFFD, while
 *  these fixtures pin the per-code-point island semantics. */
function latin1Decoded(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) out += String.fromCharCode(b);
  return out;
}

/** Seeded uniform byte stream, mirroring tests _noise_bytes. */
function noiseBytes(seed: number, size: number): Uint8Array {
  let state = seed >>> 0;
  const out = new Uint8Array(size);
  for (let i = 0; i < size; i++) {
    state = (Math.imul(state, 1103515245) + 12345) >>> 0;
    out[i] = state & 0xff;
  }
  return out;
}

const MULTIPART_CONTENT_TYPE = 'multipart/form-data; boundary=B0';

/** Mirrors the Go tests' extractValuePairs: the scan values in order, as
 *  [context, content] pairs (label first, then the part entries). */
function extractMultipartValuePairs(body: string, minRunLength = 16): [string, string][] {
  const [, params] = parseMediaTypeParams(MULTIPART_CONTENT_TYPE);
  const values: [string, string][] = [];
  for (const part of parseMultipartParts(body, params['boundary'] ?? '')) {
    const entries = multipartPartEntries(part, minRunLength);
    if (entries.length === 0) continue;
    values.push(['request_body', entries[0].label]);
    for (const entry of entries) values.push(['request_body:multipart_field', entry.value]);
  }
  return values;
}

function filePartBody(filename: string, content: string): string {
  return `--B0\r\nContent-Disposition: form-data; name="upload"; filename="${filename}"\r\n\r\n${content}\r\n--B0--\r\n`;
}

describe('extractBinaryIslands (guard-core 5f399234)', () => {
  it('keeps runs at or above the minimum length', () => {
    const content = latin1Decoded(new Uint8Array([0])) + 'abc' + latin1Decoded(new Uint8Array([0])) + 'x'.repeat(16) + latin1Decoded(new Uint8Array([0])) + 'def' + latin1Decoded(new Uint8Array([0]));
    expect(extractBinaryIslands(content, 16)).toEqual(['x'.repeat(16)]);
  });

  it('returns runs separately', () => {
    const content = latin1Decoded(new Uint8Array([0])) + 'a'.repeat(16) + latin1Decoded(new Uint8Array([0])) + 'b'.repeat(16) + latin1Decoded(new Uint8Array([0]));
    expect(extractBinaryIslands(content, 16)).toEqual(['a'.repeat(16), 'b'.repeat(16)]);
  });

  it('preserves non-ASCII text runs', () => {
    const text = 'Caf\u00e9 r\u00e9sum\u00e9 na\u00efve d\u00e9cor s\u00e9lection';
    expect(extractBinaryIslands(text, 16)).toEqual([text]);
  });

  it('returns the whole content for a minimum of 1 or below', () => {
    const content = 'anything\x00at all';
    expect(extractBinaryIslands(content, 1)).toEqual([content]);
    expect(extractBinaryIslands(content, 0)).toEqual([content]);
  });

  it('keeps tab, newline and carriage return inside runs', () => {
    const content = '\x00select 1\nfrom t\r\nwhere x=1\x00';
    expect(extractBinaryIslands(content, 16)).toEqual(['select 1\nfrom t\r\nwhere x=1']);
  });

  it('drops runs below the minimum length', () => {
    const content = '\x00' + 'a'.repeat(15) + '\x00' + 'b'.repeat(16) + '\x00';
    expect(extractBinaryIslands(content, 16)).toEqual(['b'.repeat(16)]);
  });
});

describe('valueIsBinaryLike', () => {
  it('rejects empty and text content', () => {
    expect(valueIsBinaryLike('')).toBe(false);
    expect(valueIsBinaryLike('plain text body with attack 1 OR 1=1')).toBe(false);
    expect(valueIsBinaryLike('one null\x00byte')).toBe(false);
  });

  it('accepts random noise and replacement-character junk', () => {
    expect(valueIsBinaryLike(latin1Decoded(noiseBytes(7, 4096)))).toBe(true);
    expect(valueIsBinaryLike('\ufffd'.repeat(100))).toBe(true);
  });

  it('accepts content right at the one-fifth ratio', () => {
    // 1 artifact in 5 characters reaches the 0.2 threshold.
    expect(valueIsBinaryLike('abcd\x00')).toBe(true);
    expect(valueIsBinaryLike('abcde\x00')).toBe(false);
  });
});

describe('parseFormPairs (parse_qsl keep_blank_values port)', () => {
  it('mirrors parse_qsl pair extraction', () => {
    expect(parseFormPairs('a=b&c')).toEqual([{ name: 'a', value: 'b' }, { name: 'c', value: '' }]);
    expect(parseFormPairs('a=b=c&d=&=v&+x=%2F%zz&a=b')).toEqual([
      { name: 'a', value: 'b=c' },
      { name: 'd', value: '' },
      { name: '', value: 'v' },
      { name: ' x', value: '/%zz' },
      { name: 'a', value: 'b' },
    ]);
    expect(parseFormPairs('a=1&&b=2&')).toEqual([{ name: 'a', value: '1' }, { name: 'b', value: '2' }]);
    expect(parseFormPairs('')).toEqual([]);
  });

  it('decodes valid UTF-8 percent runs as text', () => {
    expect(parseFormPairs('q=%C3%A9')).toEqual([{ name: 'q', value: '\u00e9' }]);
  });

  it('maps invalid percent bytes to replacement characters', () => {
    const [{ value }] = parseFormPairs('q=%ff%fe');
    expect(value).toBe('\ufffd\ufffd');
  });
});

describe('multipart part extraction (body_form_scan port)', () => {
  it('extracts a text part with the header entry and payload', () => {
    const body = '--B0\r\nContent-Disposition: form-data; name="note"\r\n\r\nhello\r\n--B0--\r\n';
    expect(extractMultipartValuePairs(body)).toEqual([
      ['request_body', 'note'],
      ['request_body:multipart_field', 'Content-Disposition: form-data; name="note"'],
      ['request_body:multipart_field', 'hello'],
    ]);
  });

  it('includes the filename entry and every header in wire order', () => {
    const body = '--B0\r\nContent-Disposition: form-data; name="upload"; filename="report.pdf"\r\n\r\nbinary-file-payload\r\n--B0--\r\n';
    expect(extractMultipartValuePairs(body)).toEqual([
      ['request_body', 'upload'],
      ['request_body:multipart_field', 'filename="report.pdf"'],
      ['request_body:multipart_field', 'Content-Disposition: form-data; name="upload"; filename="report.pdf"'],
      ['request_body:multipart_field', 'binary-file-payload'],
    ]);
  });

  it('falls back to the file label for parts without a name', () => {
    const body = '--B0\r\nContent-Disposition: form-data; filename="a.txt"\r\n\r\nhi\r\n--B0--\r\n';
    const values = extractMultipartValuePairs(body);
    expect(values[0]).toEqual(['request_body', 'file']);
  });

  it('yields no payload entries for an empty payload', () => {
    const body = '--B0\r\nContent-Disposition: form-data; name="f"; filename="empty.bin"\r\n\r\n\r\n--B0--\r\n';
    const values = extractMultipartValuePairs(body);
    expect(values).toEqual([
      ['request_body', 'f'],
      ['request_body:multipart_field', 'filename="empty.bin"'],
      ['request_body:multipart_field', 'Content-Disposition: form-data; name="f"; filename="empty.bin"'],
    ]);
  });

  it('unescapes paired quotes and strips quote characters from filenames', () => {
    const body = '--B0\r\nContent-Disposition: form-data; name="file"; filename="shell\\".php%00.jpg"\r\n\r\nharmless\r\n--B0--\r\n';
    const values = extractMultipartValuePairs(body);
    expect(values[1]).toEqual(['request_body:multipart_field', 'filename="shell.php%00.jpg"']);
  });

  it('strips single quotes from filenames', () => {
    const body = "--B0\r\nContent-Disposition: form-data; name=\"file\"; filename=\"shell'.php.jpg\"\r\n\r\nharmless\r\n--B0--\r\n";
    const values = extractMultipartValuePairs(body);
    expect(values[1]).toEqual(['request_body:multipart_field', 'filename="shell.php.jpg"']);
  });

  it('decodes RFC 2231 extended filename parameters', () => {
    const body = '--B0\r\nContent-Disposition: form-data; name="file"; filename*=UTF-8\'\'shell.php%0A.jpg\r\n\r\nharmless\r\n--B0--\r\n';
    const values = extractMultipartValuePairs(body);
    expect(values[1]).toEqual(['request_body:multipart_field', 'filename="shell.php\n.jpg"']);
  });

  it('keeps folded header continuations with the raw break', () => {
    const body = '--B0\r\nContent-Disposition: form-data;\r\n name="note"\r\n\r\nhello\r\n--B0--\r\n';
    const values = extractMultipartValuePairs(body);
    expect(values).toEqual([
      ['request_body', 'note'],
      ['request_body:multipart_field', 'Content-Disposition: form-data;\r\n name="note"'],
      ['request_body:multipart_field', 'hello'],
    ]);
  });

  it('treats a colonless line as the payload start', () => {
    const body = '--B0\r\nno colon here\r\nmore payload\r\n--B0--\r\n';
    const values = extractMultipartValuePairs(body);
    expect(values).toEqual([
      ['request_body', 'file'],
      ['request_body:multipart_field', 'no colon here\r\nmore payload'],
    ]);
  });

  it('keeps a part whose closing boundary is missing', () => {
    const body = '--B0\r\nContent-Disposition: form-data; name="note"\r\n\r\nhello\r\n';
    const values = extractMultipartValuePairs(body);
    expect(values).toEqual([
      ['request_body', 'note'],
      ['request_body:multipart_field', 'Content-Disposition: form-data; name="note"'],
      ['request_body:multipart_field', 'hello\r\n'],
    ]);
  });

  it('discards the preamble and the epilogue', () => {
    const body = 'preamble\r\n--B0\r\nContent-Disposition: form-data; name="note"\r\n\r\nhello\r\n--B0--\r\nepilogue\r\n';
    const values = extractMultipartValuePairs(body);
    expect(values).toEqual([
      ['request_body', 'note'],
      ['request_body:multipart_field', 'Content-Disposition: form-data; name="note"'],
      ['request_body:multipart_field', 'hello'],
    ]);
  });

  it('expands nested multipart containers in place', () => {
    const body = '--B0\r\nContent-Disposition: form-data; name="files"\r\n' +
      'Content-Type: multipart/mixed; boundary=INNER\r\n\r\n' +
      '--INNER\r\nContent-Disposition: attachment; filename="shell.php.jpg"\r\n' +
      'Content-Type: application/octet-stream\r\n\r\npayload-bytes' +
      '\r\n--INNER--\r\n--B0--\r\n';
    expect(extractMultipartValuePairs(body)).toEqual([
      ['request_body', 'file'],
      ['request_body:multipart_field', 'filename="shell.php.jpg"'],
      ['request_body:multipart_field', 'Content-Disposition: attachment; filename="shell.php.jpg"'],
      ['request_body:multipart_field', 'Content-Type: application/octet-stream'],
      ['request_body:multipart_field', 'payload-bytes'],
    ]);
  });

  it('returns no parts for a boundary mismatch (blob fallback route)', () => {
    const body = '--B0\r\nContent-Disposition: form-data; name="file"\r\n\r\nhi\r\n--B0--\r\n';
    const [, params] = parseMediaTypeParams('multipart/form-data; boundary=OTHER');
    expect(parseMultipartParts(body, params['boundary'] ?? '')).toEqual([]);
  });

  it('returns no parts without a boundary parameter', () => {
    expect(parseMultipartParts('--B0\r\n\r\nx\r\n--B0--\r\n', '')).toEqual([]);
  });
});

describe('binary islands reduction of file-part payloads', () => {
  it('reduces a binary-dense payload to the printable island pairs', () => {
    let content = '';
    for (let i = 0; i < 100; i++) {
      for (let c = 0; c < 256; c++) content += String.fromCharCode(c);
    }
    const body = '--B0\r\nContent-Disposition: form-data; name="file"; filename="photo.jpg"\r\n' +
      'Content-Type: application/octet-stream\r\n\r\n' + content + '\r\n--B0--\r\n';
    const values = extractMultipartValuePairs(body);
    let asciiRun = '';
    for (let c = 0x20; c <= 0x7e; c++) asciiRun += String.fromCharCode(c);
    let latinRun = '';
    for (let c = 0xa1; c <= 0xff; c++) latinRun += String.fromCharCode(c);
    // label name scan, filename entry, two part headers, then the island
    // pair per cycle.
    expect(values.length).toBe(4 + 2 * 100);
    expect(values[0]).toEqual(['request_body', 'file']);
    expect(values[1]).toEqual(['request_body:multipart_field', 'filename="photo.jpg"']);
    expect(values[4][1]).toBe(asciiRun);
    expect(values[5][1]).toBe(latinRun);
  });

  it('keeps the full payload when no filename makes the part a text part', () => {
    let content = '';
    for (let i = 0; i < 20; i++) {
      for (let c = 0; c < 256; c++) content += String.fromCharCode(c);
    }
    const body = '--B0\r\nContent-Disposition: form-data; name="blob"\r\n\r\n' + content + '\r\n--B0--\r\n';
    const values = extractMultipartValuePairs(body);
    // label scan, header entry, then the whole binary payload as one value.
    expect(values.length).toBe(3);
    expect(values[2][1]).toBe(content);
  });

  it('honors a raised minimum run length', () => {
    let content = '';
    for (let i = 0; i < 10; i++) {
      for (let c = 0; c < 256; c++) content += String.fromCharCode(c);
    }
    content += '\x00<script>alert(1)</script>\x00';
    const body = '--B0\r\nContent-Disposition: form-data; name="file"; filename="dump.bin"\r\n\r\n' + content + '\r\n--B0--\r\n';
    const defaultValues = extractMultipartValuePairs(body);
    expect(defaultValues.some(([, value]) => value === '<script>alert(1)</script>')).toBe(true);
    const raisedValues = extractMultipartValuePairs(body, 1024);
    expect(raisedValues.some(([, value]) => value.includes('script'))).toBe(false);
  });
});
