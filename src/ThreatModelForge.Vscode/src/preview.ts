const attribute = (value: string) => value.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;');

export function studioHtml(cspSource: string, script: string, style: string, nonce: string): string {
  return `<!doctype html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src ${attribute(cspSource)} data: blob:; style-src ${attribute(cspSource)} 'unsafe-inline'; font-src ${attribute(cspSource)}; script-src 'nonce-${attribute(nonce)}'; connect-src 'none'; base-uri 'none'; form-action 'none';">
<link rel="stylesheet" href="${attribute(style)}"><title>Threat Model Forge Studio</title></head>
<body><div id="root"></div><script nonce="${attribute(nonce)}" type="module" src="${attribute(script)}"></script></body></html>`;
}
