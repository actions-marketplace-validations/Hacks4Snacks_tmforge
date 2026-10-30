import { parentPort, workerData } from 'node:worker_threads';
import { pathToFileURL } from 'node:url';
import { join } from 'node:path';
import { ENGINE_METHODS, MAX_DOCUMENT_BYTES, MAX_REQUEST_BYTES } from './engine.js';

globalThis.fetch = async () => { throw new Error('The bundled analysis engine cannot access the network.'); };

const engine = (async () => {
  const { dotnet } = await import(pathToFileURL(join(workerData.runtimeDirectory, 'dotnet.js')).href);
  const runtime = await dotnet.create();
  const exports = await runtime.getAssemblyExports(runtime.getConfig().mainAssemblyName);
  const api = exports.ThreatModelForge.Wasm.Engine;
  if (typeof api.InspectFile !== 'function') throw new Error('The bundled engine is missing InspectFile. Rebuild the extension assets.');
  return api;
})();

let queue = Promise.resolve();
let customRules = false;
parentPort.on('message', request => {
  queue = queue.then(async () => {
    try {
      const api = await engine;
      let result;
      if (request.method !== undefined) {
        if (!Object.hasOwn(ENGINE_METHODS, request.method) || !Array.isArray(request.args)
          || request.args.length !== ENGINE_METHODS[request.method] || request.args.some(value => typeof value !== 'string')
          || request.args.reduce((size, value) => size + Buffer.byteLength(value, 'utf8'), 0) > MAX_REQUEST_BYTES) {
          throw new Error('Unsupported engine operation or arguments.');
        }
        result = api[request.method](...request.args);
        if (request.method === 'SetRules') customRules = request.args[0] !== '';
      } else {
        if (!(request.bytes instanceof Uint8Array) || request.bytes.byteLength > MAX_DOCUMENT_BYTES) {
          throw new Error('Model inspection is limited to 8 MiB.');
        }
        result = JSON.parse(api.InspectFile(Buffer.from(request.bytes).toString('base64'), request.format ?? ''));
        if (customRules && result.format === 'tmforge-json' && result.analysis) {
          result.analysis = JSON.parse(api.Analysis(new TextDecoder().decode(request.bytes)));
        }
      }
      if (Buffer.byteLength(typeof result === 'string' ? result : JSON.stringify(result), 'utf8') > 16 * 1024 * 1024) {
        throw new Error('The engine exceeds the 16 MiB result limit.');
      }
      parentPort.postMessage({ id: request.id, result });
    } catch (error) {
      parentPort.postMessage({ id: request.id, error: String(error?.message ?? error).slice(0, 2048) });
    }
  });
});

engine.catch(() => {});
