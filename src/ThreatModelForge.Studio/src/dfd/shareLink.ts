export const SHARE_PREFIX = '#tmforge=';
export const MAX_SHARE_URL_LENGTH = 16 * 1024;
export const MAX_SHARE_MODEL_BYTES = 1024 * 1024;

const VERSION = '1';

export async function createShareUrl(json: string, pageUrl: string): Promise<string> {
  const bytes = new TextEncoder().encode(json);
  if (bytes.length > MAX_SHARE_MODEL_BYTES) {
    throw new Error('This model exceeds the 1 MiB share limit. Download the model instead.');
  }
  if (typeof CompressionStream === 'undefined') {
    throw new Error('This browser cannot compress share links. Download the model instead.');
  }
  let compressed: Uint8Array<ArrayBuffer>;
  try {
    compressed = await transform(bytes, new CompressionStream('gzip'), MAX_SHARE_URL_LENGTH);
  } catch (error) {
    if (error instanceof RangeError) {
      throw new Error('This model exceeds the 16 KiB share-link limit. Download the model instead.');
    }
    throw error;
  }
  const url = new URL(pageUrl);
  url.username = '';
  url.password = '';
  url.search = '';
  url.hash = `${SHARE_PREFIX}${VERSION}.${base64url(compressed)}`;
  if (url.href.length > MAX_SHARE_URL_LENGTH) {
    throw new Error('This model exceeds the 16 KiB share-link limit. Download the model instead.');
  }
  return url.href;
}

export async function readShareFragment(fragment: string): Promise<string | null> {
  if (!fragment.startsWith(SHARE_PREFIX)) return null;
  if (fragment.length > MAX_SHARE_URL_LENGTH) {
    throw new Error('This share link exceeds the 16 KiB limit. Ask the sender for a model file.');
  }
  const envelope = fragment.slice(SHARE_PREFIX.length);
  const separator = envelope.indexOf('.');
  if (separator < 0 || envelope.slice(0, separator) !== VERSION) {
    throw new Error('Unsupported share-link version. Open it with a compatible Studio version or request a model file.');
  }
  if (typeof DecompressionStream === 'undefined') {
    throw new Error('This browser cannot open compressed share links. Use a browser with DecompressionStream support or request a model file.');
  }
  const payload = envelope.slice(separator + 1);
  if (!/^[A-Za-z0-9_-]+$/.test(payload) || payload.length % 4 === 1) {
    throw new Error('Invalid share-link encoding. Ask the sender for a complete link or a model file.');
  }
  const binary = atob(payload.replace(/-/g, '+').replace(/_/g, '/'));
  const compressed = Uint8Array.from(binary, character => character.charCodeAt(0));
  if (base64url(compressed) !== payload) {
    throw new Error('Invalid share-link encoding. Ask the sender for a complete link or a model file.');
  }
  let decoded: Uint8Array<ArrayBuffer>;
  try {
    decoded = await transform(compressed, new DecompressionStream('gzip'), MAX_SHARE_MODEL_BYTES);
  } catch (error) {
    if (error instanceof RangeError) {
      throw new Error('The shared model exceeds the 1 MiB decoded limit. Ask the sender for a model file.');
    }
    throw new Error('The share link is damaged or incomplete. Ask the sender for a complete link or a model file.');
  }
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(decoded);
  } catch {
    throw new Error('The shared model is not valid UTF-8. Ask the sender for a model file.');
  }
}

function base64url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function transform(
  bytes: Uint8Array<ArrayBuffer>,
  stream: CompressionStream | DecompressionStream,
  limit: number,
): Promise<Uint8Array<ArrayBuffer>> {
  const source = new ReadableStream<Uint8Array<ArrayBuffer>>({
    start(controller) {
      controller.enqueue(bytes);
      controller.close();
    },
  });
  const reader = source.pipeThrough(stream).getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) break;
      length += chunk.value.byteLength;
      if (length > limit) {
        await reader.cancel();
        throw new RangeError('This model exceeds the share-link size limit. Download the model instead.');
      }
      chunks.push(chunk.value);
    }
  } finally {
    reader.releaseLock();
  }
  const output = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return output;
}
