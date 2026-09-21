import { describe, expect, it, vi, afterEach } from 'vitest';
import { createShareUrl, MAX_SHARE_MODEL_BYTES, MAX_SHARE_URL_LENGTH, readShareFragment, SHARE_PREFIX } from './shareLink';

afterEach(() => vi.unstubAllGlobals());

const json = JSON.stringify({
  schema: 'tmforge-json', version: '0.1',
  elements: [{ id: 'api', kind: 'process', name: 'API', x: 12, y: -30, width: 160, height: 100, properties: { AuthenticationScheme: 'Unknown' } }],
  flows: [], metadata: { owner: 'Reviewer', highLevelSystemDescription: '\u03b1 / # + & ? %' },
  analysis: { expectedPacks: [{ id: 'policy', fingerprint: 'sha256:pin' }] },
  threats: [{ id: 'manual:one', manual: true, state: 'Accepted', justification: 'Recorded decision.' }],
});

async function fragmentFor(bytes: Uint8Array<ArrayBuffer>): Promise<string> {
  const source = new ReadableStream({ start(controller) { controller.enqueue(bytes); controller.close(); } });
  const compressed = new Uint8Array(await new Response(source.pipeThrough(new CompressionStream('gzip'))).arrayBuffer());
  return `${SHARE_PREFIX}1.${btoa(String.fromCharCode(...compressed)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')}`;
}

describe('versioned share links', () => {
  it('round-trips the exact UTF-8 JSON without a network request', async () => {
    const fetch = vi.fn();
    vi.stubGlobal('fetch', fetch);
    const link = await createShareUrl(json, 'https://user:password@example.test/tmforge/?session=private#old');
    const url = new URL(link);
    expect(url.pathname).toBe('/tmforge/');
    expect(url.search).toBe('');
    expect(url.username).toBe('');
    expect(url.password).toBe('');
    expect(url.hash).toMatch(/^#tmforge=1\.[A-Za-z0-9_-]+$/);
    expect(await readShareFragment(url.hash)).toBe(json);
    expect(fetch).not.toHaveBeenCalled();
  });

  it('uses deterministic compression without changing the source URL', async () => {
    const base = 'https://example.test/studio/';
    expect(await createShareUrl(json, base)).toBe(await createShareUrl(json, base));
    expect(base).toBe('https://example.test/studio/');
  });

  it.each(['', '#outline', '#other=1.value'])('ignores unrelated fragments: %s', async fragment => {
    expect(await readShareFragment(fragment)).toBeNull();
  });

  it.each(['#tmforge=2.abcd', '#tmforge=1', '#tmforge='])('refuses unknown or missing versions: %s', async fragment => {
    await expect(readShareFragment(fragment)).rejects.toThrow(/version/i);
  });

  it.each(['', 'A', 'a%20b', 'abcd=', 'a+b', 'a/b', 'AB'])('refuses malformed base64url: %s', async payload => {
    await expect(readShareFragment(`${SHARE_PREFIX}1.${payload}`)).rejects.toThrow(/encoding/i);
  });

  it('rejects truncated and non-gzip payloads', async () => {
    const fragment = new URL(await createShareUrl(json, 'https://example.test/')).hash;
    await expect(readShareFragment(fragment.slice(0, -8))).rejects.toThrow(/damaged|encoding/i);
    await expect(readShareFragment('#tmforge=1.aGVsbG8')).rejects.toThrow(/damaged/i);
  });

  it('caps encoded input before attempting decompression', async () => {
    await expect(readShareFragment('#tmforge=1.' + 'a'.repeat(MAX_SHARE_URL_LENGTH))).rejects.toThrow(/16 KiB/);
  });

  it('caps source bytes and the complete URL without returning a truncated link', async () => {
    await expect(createShareUrl('x'.repeat(MAX_SHARE_MODEL_BYTES + 1), 'https://example.test/')).rejects.toThrow(/1 MiB/);
    await expect(createShareUrl(json, 'https://example.test/' + 'a'.repeat(MAX_SHARE_URL_LENGTH))).rejects.toThrow(/16 KiB/);
    await expect(createShareUrl('\u00e9'.repeat(MAX_SHARE_MODEL_BYTES / 2 + 1), 'https://example.test/')).rejects.toThrow(/1 MiB/);
  });

  it('rejects a poorly compressible model instead of truncating the encoded URL', async () => {
    let state = 123456789;
    const characters = Array.from({ length: 48000 }, () => {
      state ^= state << 13;
      state ^= state >>> 17;
      state ^= state << 5;
      return String.fromCharCode(33 + ((state >>> 0) % 90));
    });
    await expect(createShareUrl(JSON.stringify({ description: characters.join('') }), 'https://example.test/')).rejects.toThrow(/16 KiB/);
  });

  it('stops decompression bombs at the decoded byte limit', async () => {
    const fragment = await fragmentFor(new TextEncoder().encode('x'.repeat(MAX_SHARE_MODEL_BYTES + 1)));
    await expect(readShareFragment(fragment)).rejects.toThrow(/1 MiB decoded/);
  });

  it('refuses invalid UTF-8 after successful gzip decompression', async () => {
    const fragment = await fragmentFor(new Uint8Array([0xff, 0xfe]));
    await expect(readShareFragment(fragment)).rejects.toThrow(/UTF-8/);
  });

  it('reports missing browser compression support with a file fallback', async () => {
    vi.stubGlobal('CompressionStream', undefined);
    await expect(createShareUrl(json, 'https://example.test/')).rejects.toThrow(/Download the model/);
    vi.stubGlobal('DecompressionStream', undefined);
    await expect(readShareFragment('#tmforge=1.abcd')).rejects.toThrow(/DecompressionStream/);
  });
});
