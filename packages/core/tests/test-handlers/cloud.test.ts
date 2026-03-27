import { describe, it, expect, vi, beforeEach } from 'vitest';
import { CloudHandler } from '../../src/handlers/cloud.js';
import { defaultLogger } from '../../src/models/logger.js';

const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

describe('CloudHandler', () => {
  let handler: CloudHandler;

  beforeEach(() => {
    handler = new CloudHandler(defaultLogger);
    mockFetch.mockReset();
  });

  it('isCloudIp returns false with no ranges loaded', () => {
    expect(handler.isCloudIp('1.2.3.4', new Set(['AWS']))).toBe(false);
  });

  it('isCloudIp returns false for invalid IP', () => {
    expect(handler.isCloudIp('not-an-ip', new Set(['AWS']))).toBe(false);
  });

  it('getCloudProviderDetails returns null with no ranges', () => {
    expect(handler.getCloudProviderDetails('1.2.3.4', new Set(['AWS']))).toBeNull();
  });

  it('refreshAsync fetches AWS ranges', async () => {
    mockFetch.mockResolvedValueOnce({
      json: async () => ({ prefixes: [{ ip_prefix: '52.0.0.0/8', service: 'AMAZON' }] }),
    });

    await handler.refreshAsync(new Set(['AWS']));
    expect(handler.isCloudIp('52.1.2.3', new Set(['AWS']))).toBe(true);
    expect(handler.isCloudIp('8.8.8.8', new Set(['AWS']))).toBe(false);
  });

  it('refreshAsync fetches GCP ranges', async () => {
    mockFetch.mockResolvedValueOnce({
      json: async () => ({ prefixes: [{ ipv4Prefix: '35.0.0.0/8' }] }),
    });

    await handler.refreshAsync(new Set(['GCP']));
    expect(handler.isCloudIp('35.1.2.3', new Set(['GCP']))).toBe(true);
  });

  it('refreshAsync handles Azure (two-step fetch)', async () => {
    mockFetch
      .mockResolvedValueOnce({
        text: async () => '<a href="https://download.microsoft.com/test.json">Download</a>',
      })
      .mockResolvedValueOnce({
        json: async () => ({ values: [{ properties: { addressPrefixes: ['40.0.0.0/8'] } }] }),
      });

    await handler.refreshAsync(new Set(['Azure']));
    expect(handler.isCloudIp('40.1.2.3', new Set(['Azure']))).toBe(true);
  });

  it('refreshAsync handles Azure with no download URL', async () => {
    mockFetch.mockResolvedValueOnce({
      text: async () => '<html>No download link here</html>',
    });

    await handler.refreshAsync(new Set(['Azure']));
    expect(handler.isCloudIp('40.1.2.3', new Set(['Azure']))).toBe(false);
  });

  it('refreshAsync handles fetch failure gracefully', async () => {
    mockFetch.mockRejectedValueOnce(new Error('network error'));
    await handler.refreshAsync(new Set(['AWS']));
  });

  it('getCloudProviderDetails returns provider and CIDR', async () => {
    mockFetch.mockResolvedValueOnce({
      json: async () => ({ prefixes: [{ ip_prefix: '52.0.0.0/8', service: 'AMAZON' }] }),
    });

    await handler.refreshAsync(new Set(['AWS']));
    const result = handler.getCloudProviderDetails('52.1.2.3', new Set(['AWS']));
    expect(result).not.toBeNull();
    expect(result![0]).toBe('AWS');
    expect(result![1]).toBe('52.0.0.0/8');
  });

  it('reset clears all ranges', async () => {
    mockFetch.mockResolvedValueOnce({
      json: async () => ({ prefixes: [{ ip_prefix: '52.0.0.0/8', service: 'AMAZON' }] }),
    });

    await handler.refreshAsync(new Set(['AWS']));
    expect(handler.isCloudIp('52.1.2.3', new Set(['AWS']))).toBe(true);

    await handler.reset();
    expect(handler.isCloudIp('52.1.2.3', new Set(['AWS']))).toBe(false);
  });

  it('initializeAgent sets handler', async () => {
    const agent = { sendEvent: vi.fn() };
    await handler.initializeAgent(agent as never);
  });

  it('handles unknown provider', async () => {
    mockFetch.mockResolvedValueOnce({ json: async () => ({}) });
    await handler.refreshAsync(new Set(['Unknown' as 'AWS']));
  });

  it('loads from Redis when fetch fails', async () => {
    mockFetch.mockRejectedValue(new Error('network'));

    const mockRedis = {
      getKey: vi.fn().mockResolvedValue('10.0.0.0/8'),
      setKey: vi.fn(),
      deletePattern: vi.fn(),
    };
    await handler.initializeRedis(mockRedis as never, new Set(['AWS']));
    expect(handler.isCloudIp('10.1.2.3', new Set(['AWS']))).toBe(true);
  });

  it('initializeAgent + refreshAsync with agent', async () => {
    const agent = { sendEvent: vi.fn() };
    await handler.initializeAgent(agent as never);

    mockFetch.mockResolvedValue({
      json: async () => ({ prefixes: [{ ip_prefix: '1.0.0.0/8', service: 'AMAZON' }] }),
    });

    await handler.refreshAsync(new Set(['AWS']));
  });
});
