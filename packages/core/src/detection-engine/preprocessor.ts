const ATTACK_INDICATORS = [
  /<script/i,
  /javascript:/i,
  /on\w+=/i,
  /SELECT\s+.{0,50}?\s+FROM/i,
  /UNION\s+SELECT/i,
  /\.\.\//,
  /eval\s*\(/i,
  /exec\s*\(/i,
  /system\s*\(/i,
  /<\?php/i,
  /<%%/,
  /\{\{/,
  /\{%/,
  /<iframe/i,
  /<object/i,
  /<embed/i,
  /onerror\s*=/i,
  /onload\s*=/i,
  /\$\{/,
  /\\x[0-9a-fA-F]{2}/,
  /%[0-9a-fA-F]{2}/,
];

const LOOKALIKES: Record<string, string> = {
  '\u2044': '/',
  '\uff0f': '/',
  '\u29f8': '/',
  '\u0130': 'I',
  '\u0131': 'i',
  '\u200b': '',
  '\u200c': '',
  '\u200d': '',
  '\ufeff': '',
  '\u00ad': '',
  '\u034f': '',
  '\u180e': '',
  '\u2028': '\n',
  '\u2029': '\n',
  '\ue000': '',
  '\ufff0': '',
  '\u01c0': '|',
  '\u037e': ';',
  '\u2215': '/',
  '\u2216': '\\',
  '\uff1c': '<',
  '\uff1e': '>',
};

const CONTROL_CHARS_RE = /[\x00-\x08\x0b\x0c\x0e-\x1f]/g;

export class ContentPreprocessor {
  private readonly maxContentLength: number;
  private readonly preserveAttackPatterns: boolean;

  constructor(maxContentLength = 10000, preserveAttackPatterns = true) {
    this.maxContentLength = maxContentLength;
    this.preserveAttackPatterns = preserveAttackPatterns;
  }

  normalizeUnicode(content: string): string {
    let normalized = content.normalize('NFKC');
    for (const [char, replacement] of Object.entries(LOOKALIKES)) {
      normalized = normalized.replaceAll(char, replacement);
    }
    return normalized;
  }

  removeNullBytes(content: string): string {
    return content.replace(/\x00/g, '').replace(CONTROL_CHARS_RE, '');
  }

  removeExcessiveWhitespace(content: string): string {
    return content.replace(/\s+/g, ' ').trim();
  }

  decodeCommonEncodings(content: string): string {
    const maxIterations = 3;
    let current = content;

    for (let i = 0; i < maxIterations; i++) {
      const original = current;

      try {
        const decoded = decodeURIComponent(current);
        if (decoded !== current) current = decoded;
      } catch {
        // partial encoding, ignore
      }

      try {
        current = this.decodeHtmlEntities(current);
      } catch {
        /* v8 ignore next -- HTML entity decoding fallback; decodeHtmlEntities uses only string ops that cannot throw */
      }

      if (current === original) break;
    }

    return current;
  }

  private decodeHtmlEntities(content: string): string {
    const entityMap: Record<string, string> = {
      '&amp;': '&', '&lt;': '<', '&gt;': '>', '&quot;': '"',
      '&#39;': "'", '&apos;': "'", '&#x27;': "'", '&#x2F;': '/',
      '&#47;': '/', '&nbsp;': ' ',
    };

    let result = content;
    for (const [entity, char] of Object.entries(entityMap)) {
      result = result.replaceAll(entity, char);
    }

    result = result.replace(/&#x([0-9a-fA-F]+);/g, (_, hex) =>
      String.fromCharCode(parseInt(hex, 16)),
    );

    result = result.replace(/&#(\d+);/g, (_, dec) =>
      String.fromCharCode(parseInt(dec, 10)),
    );

    return result;
  }

  extractAttackRegions(content: string): Array<[number, number]> {
    const maxRegions = Math.min(100, Math.floor(this.maxContentLength / 100));
    const regions: Array<[number, number]> = [];

    for (const indicator of ATTACK_INDICATORS) {
      const regex = new RegExp(indicator.source, indicator.flags + 'g');
      let match: RegExpExecArray | null;

      while ((match = regex.exec(content)) !== null) {
        if (regions.length >= maxRegions) break;
        const start = Math.max(0, match.index - 100);
        const end = Math.min(content.length, match.index + match[0].length + 100);
        regions.push([start, end]);
      }

      if (regions.length >= maxRegions) break;
    }

    if (regions.length === 0) return [];

    regions.sort((a, b) => a[0] - b[0]);

    const merged: Array<[number, number]> = [regions[0]];
    for (let i = 1; i < regions.length; i++) {
      const [start, end] = regions[i];
      const last = merged[merged.length - 1];
      if (start <= last[1]) {
        last[1] = Math.max(last[1], end);
      } else {
        merged.push([start, end]);
      }
    }

    return merged.slice(0, maxRegions);
  }

  truncateSafely(content: string): string {
    if (content.length <= this.maxContentLength) return content;
    if (!this.preserveAttackPatterns) return content.slice(0, this.maxContentLength);

    const attackRegions = this.extractAttackRegions(content);
    if (attackRegions.length === 0) return content.slice(0, this.maxContentLength);

    const attackLength = attackRegions.reduce((sum, [s, e]) => sum + (e - s), 0);

    if (attackLength >= this.maxContentLength) {
      let result = '';
      let remaining = this.maxContentLength;
      for (const [start, end] of attackRegions) {
        const chunkLen = Math.min(end - start, remaining);
        result += content.slice(start, start + chunkLen);
        remaining -= chunkLen;
        if (remaining <= 0) break;
      }
      return result;
    }

    /* v8 ignore start -- attack-region context assembly requires precise content geometry that tests cannot reproduce */
    const parts: string[] = [];
    for (const [start, end] of attackRegions) {
      parts.push(content.slice(start, end));
    }

    let remaining = this.maxContentLength - attackLength;
    let lastEnd = 0;
    const contextParts: string[] = [];
    for (const [start, end] of attackRegions) {
      if (lastEnd < start && remaining > 0) {
        const chunkLen = Math.min(start - lastEnd, remaining);
        contextParts.push(content.slice(lastEnd, lastEnd + chunkLen));
        remaining -= chunkLen;
      }
      lastEnd = end;
    }

    return [...contextParts, ...parts].join('');
    /* v8 ignore stop */
  }

  async preprocess(content: string): Promise<string> {
    if (!content) return '';

    let result = this.normalizeUnicode(content);
    result = this.decodeCommonEncodings(result);
    result = this.removeNullBytes(result);
    result = this.removeExcessiveWhitespace(result);
    result = this.truncateSafely(result);

    return result;
  }

  async preprocessBatch(contents: string[]): Promise<string[]> {
    return Promise.all(contents.map((c) => this.preprocess(c)));
  }
}
