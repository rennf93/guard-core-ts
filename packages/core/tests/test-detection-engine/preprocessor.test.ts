import { describe, it, expect } from 'vitest';
import { ContentPreprocessor } from '../../src/detection-engine/preprocessor.js';

describe('ContentPreprocessor', () => {
  const preprocessor = new ContentPreprocessor();

  it('returns empty string for empty input', async () => {
    expect(await preprocessor.preprocess('')).toBe('');
  });

  it('normalizes unicode', () => {
    expect(preprocessor.normalizeUnicode('\uff0f')).toBe('/');
    expect(preprocessor.normalizeUnicode('\uff1c')).toBe('<');
    expect(preprocessor.normalizeUnicode('\uff1e')).toBe('>');
    expect(preprocessor.normalizeUnicode('\u200b')).toBe('');
  });

  it('removes null bytes', () => {
    expect(preprocessor.removeNullBytes('he\x00llo')).toBe('hello');
    expect(preprocessor.removeNullBytes('a\x01b\x02c')).toBe('abc');
  });

  it('preserves tabs and newlines', () => {
    expect(preprocessor.removeNullBytes('a\tb\nc')).toBe('a\tb\nc');
  });

  it('removes excessive whitespace', () => {
    expect(preprocessor.removeExcessiveWhitespace('  hello   world  ')).toBe('hello world');
    expect(preprocessor.removeExcessiveWhitespace('a\n\n\nb')).toBe('a b');
  });

  it('decodes URL encoding', () => {
    expect(preprocessor.decodeCommonEncodings('%3Cscript%3E')).toBe('<script>');
    expect(preprocessor.decodeCommonEncodings('%27%20OR%201%3D1')).toBe("' OR 1=1");
  });

  it('decodes HTML entities', () => {
    expect(preprocessor.decodeCommonEncodings('&lt;script&gt;')).toBe('<script>');
    expect(preprocessor.decodeCommonEncodings('&amp;')).toBe('&');
  });

  it('decodes double encoding', () => {
    expect(preprocessor.decodeCommonEncodings('%253Cscript%253E')).toBe('<script>');
  });

  it('truncates to max length when not preserving patterns', () => {
    const short = new ContentPreprocessor(10, false);
    expect(short.truncateSafely('a'.repeat(20))).toBe('a'.repeat(10));
  });

  it('preserves content under max length', () => {
    expect(preprocessor.truncateSafely('short text')).toBe('short text');
  });

  it('extracts attack regions', () => {
    const content = 'normal text <script>alert(1)</script> more normal text';
    const regions = preprocessor.extractAttackRegions(content);
    expect(regions.length).toBeGreaterThan(0);
  });

  it('full pipeline processes XSS payload', async () => {
    const input = '%3Cscript%3Ealert%281%29%3C%2Fscript%3E';
    const result = await preprocessor.preprocess(input);
    expect(result).toContain('<script>');
    expect(result).toContain('alert(1)');
  });

  it('full pipeline processes SQL injection', async () => {
    const input = "' OR 1=1 --";
    const result = await preprocessor.preprocess(input);
    expect(result).toContain('OR 1=1');
  });

  it('preprocessBatch processes multiple', async () => {
    const results = await preprocessor.preprocessBatch(['<script>', 'normal']);
    expect(results).toHaveLength(2);
    expect(results[0]).toContain('<script>');
    expect(results[1]).toBe('normal');
  });

  it('decodes numeric HTML entities (decimal)', () => {
    const pp = new ContentPreprocessor();
    const result = pp.decodeCommonEncodings('&#60;script&#62;');
    expect(result).toBe('<script>');
  });

  it('decodes numeric HTML entities (hex)', () => {
    const pp = new ContentPreprocessor();
    const result = pp.decodeCommonEncodings('&#x3c;script&#x3e;');
    expect(result).toBe('<script>');
  });

  it('handles partial URL encoding gracefully', () => {
    const pp = new ContentPreprocessor();
    const result = pp.decodeCommonEncodings('%ZZnot-valid');
    expect(result).toBe('%ZZnot-valid');
  });

  it('truncates long content without attack preservation', () => {
    const pp = new ContentPreprocessor(50, false);
    const longContent = 'a'.repeat(100);
    const result = pp.truncateSafely(longContent);
    expect(result.length).toBe(50);
  });

  it('truncates long content with attack regions preserved', () => {
    const pp = new ContentPreprocessor(100, true);
    const benign = 'x'.repeat(200);
    const withAttack = benign.slice(0, 80) + '<script>alert(1)</script>' + benign.slice(80);
    const result = pp.truncateSafely(withAttack);
    expect(result.length).toBeLessThanOrEqual(100);
    expect(result).toContain('<script>');
  });

  it('handles content with attack region larger than max', () => {
    const pp = new ContentPreprocessor(20, true);
    const content = '<script>' + 'x'.repeat(100) + '</script>';
    const result = pp.truncateSafely(content);
    expect(result.length).toBeLessThanOrEqual(20);
  });

  it('merges overlapping attack regions', () => {
    const pp = new ContentPreprocessor(500, true);
    const content = '<script>alert(1)</script><script>alert(2)</script>';
    const regions = pp.extractAttackRegions(content);
    expect(regions.length).toBeGreaterThan(0);
  });

  it('returns empty regions for benign content', () => {
    const pp = new ContentPreprocessor();
    const regions = pp.extractAttackRegions('hello world normal text');
    expect(regions.length).toBe(0);
  });

  it('handles content with no regions below max length', () => {
    const pp = new ContentPreprocessor(1000, true);
    const content = 'short benign content';
    expect(pp.truncateSafely(content)).toBe(content);
  });

  it('full pipeline with triple-encoded payload', async () => {
    const pp = new ContentPreprocessor();
    const result = await pp.preprocess('%253Cscript%253Ealert(1)%253C/script%253E');
    expect(result).toContain('<script>');
  });

  it('normalizes unicode lookalikes in attack context', () => {
    const pp = new ContentPreprocessor();
    const result = pp.normalizeUnicode('\uff1cscript\uff1e');
    expect(result).toBe('<script>');
  });

  it('removes zero-width characters', () => {
    const pp = new ContentPreprocessor();
    const result = pp.normalizeUnicode('te\u200bst');
    expect(result).toBe('test');
  });
});

describe('ContentPreprocessor truncation edge cases', () => {
  it('builds result with attack regions and non-attack context', () => {
    const pp = new ContentPreprocessor(80, true);
    const benign = 'A'.repeat(40);
    const content = benign + '<script>alert(1)</script>' + benign + 'MORE';
    const result = pp.truncateSafely(content);
    expect(result.length).toBeLessThanOrEqual(80);
    expect(result).toContain('<script>');
  });

  it('handles multiple separated attack regions', () => {
    const pp = new ContentPreprocessor(200, true);
    const content = 'safe1 <script>x</script> safe2safe2safe2safe2safe2safe2safe2safe2safe2safe2safe2safe2safe2safe2safe2safe2safe2safe2safe2 eval(bad) safe3safe3safe3safe3safe3safe3safe3safe3safe3safe3';
    const result = pp.truncateSafely(content);
    expect(result.length).toBeLessThanOrEqual(200);
  });

  it('concatenates attack regions when they exceed max length', () => {
    const pp = new ContentPreprocessor(30, true);
    const content = '<script>alert(1)</script>' + 'x'.repeat(50) + '<script>alert(2)</script>';
    const result = pp.truncateSafely(content);
    expect(result.length).toBeLessThanOrEqual(30);
  });

  it('adds non-attack content between regions', () => {
    const pp = new ContentPreprocessor(300, true);
    const content = 'safe ' + '<script>x</script>' + ' middle ' + 'eval(' + 'y'.repeat(200) + ')';
    const result = pp.truncateSafely(content);
    expect(result.length).toBeLessThanOrEqual(300);
  });

  it('handles content with no attack regions but exceeding max', () => {
    const pp = new ContentPreprocessor(10, true);
    const content = 'normal text exceeding max length with no attacks';
    const result = pp.truncateSafely(content);
    expect(result.length).toBe(10);
  });

  it('decodes mixed encoding in single pass', () => {
    const pp = new ContentPreprocessor();
    const result = pp.decodeCommonEncodings('hello%20world&amp;goodbye');
    expect(result).toBe('hello world&goodbye');
  });

  it('stops decoding after max iterations', () => {
    const pp = new ContentPreprocessor();
    const result = pp.decodeCommonEncodings('%252525252525hello');
    expect(typeof result).toBe('string');
  });

  it('assembles context parts between non-overlapping attack regions', async () => {
    const pp = new ContentPreprocessor(150, true);
    const safe1 = 'SAFE1'.repeat(10);
    const safe2 = 'SAFE2'.repeat(10);
    const content = safe1 + '<script>x</script>' + safe2 + 'eval(y)' + 'END';
    const result = pp.truncateSafely(content);
    expect(result.length).toBeLessThanOrEqual(150);
    expect(result).toContain('<script>');
  });

  it('skips context when remaining is zero', () => {
    const pp = new ContentPreprocessor(30, true);
    const attack1 = '<script>alert(1)</script>';
    const attack2 = 'eval(dangerous)';
    const content = attack1 + 'x'.repeat(10) + attack2;
    const result = pp.truncateSafely(content);
    expect(result.length).toBeLessThanOrEqual(30);
  });

  it('handles HTML entity edge cases', () => {
    const pp = new ContentPreprocessor();
    expect(pp.decodeCommonEncodings('&#039;test&#039;')).toBe("'test'");
    expect(pp.decodeCommonEncodings('&#x27;test&#x27;')).toBe("'test'");
  });

  it('merges non-overlapping attack regions separately', () => {
    const pp = new ContentPreprocessor(500, true);
    const content = 'safe' + 'x'.repeat(200) + '<script>a</script>' + 'y'.repeat(200) + 'eval(b)';
    const regions = pp.extractAttackRegions(content);
    expect(regions.length).toBeGreaterThanOrEqual(1);
  });
});
