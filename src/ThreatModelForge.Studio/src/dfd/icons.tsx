import type { ReactNode } from 'react';
import type { DfdKind } from './types';
import appServiceUrl from '../assets/azure/app-service.svg';
import functionUrl from '../assets/azure/function.svg';
import aksUrl from '../assets/azure/aks.svg';
import vmUrl from '../assets/azure/vm.svg';
import sqlUrl from '../assets/azure/sql.svg';
import cosmosUrl from '../assets/azure/cosmos.svg';
import blobUrl from '../assets/azure/blob.svg';
import serviceBusUrl from '../assets/azure/service-bus.svg';
import entraIdUrl from '../assets/azure/entra-id.svg';
import keyVaultUrl from '../assets/azure/key-vault.svg';
import managedIdentityUrl from '../assets/azure/managed-identity.svg';
import vnetUrl from '../assets/azure/vnet.svg';
import subnetUrl from '../assets/azure/subnet.svg';
import appGatewayUrl from '../assets/azure/app-gateway.svg';
import privateEndpointUrl from '../assets/azure/private-endpoint.svg';

/**
 * A cohesive line-icon set (24×24 grid, 1.75 stroke, `currentColor`) so every stencil shares one
 * visual language and inherits its color from CSS. Replaces the per-platform emoji glyphs.
 */
const ICONS: Record<string, ReactNode> = {
  // --- generic DFD primitives ---
  cpu: (
    <>
      <rect x="6" y="6" width="12" height="12" rx="2" />
      <rect x="9.5" y="9.5" width="5" height="5" rx="1" />
      <path d="M9.5 3v3M14.5 3v3M9.5 18v3M14.5 18v3M3 9.5h3M3 14.5h3M18 9.5h3M18 14.5h3" />
    </>
  ),
  database: (
    <>
      <ellipse cx="12" cy="5.5" rx="7" ry="2.6" />
      <path d="M5 5.5v13c0 1.4 3.1 2.5 7 2.5s7-1.1 7-2.5v-13" />
      <path d="M5 12c0 1.4 3.1 2.6 7 2.6s7-1.2 7-2.6" />
    </>
  ),
  monitor: (
    <>
      <rect x="3" y="4" width="18" height="12" rx="2" />
      <path d="M8.5 20h7M12 16v4" />
    </>
  ),
  boundary: <rect x="3.5" y="3.5" width="17" height="17" rx="3" strokeDasharray="3.5 3" />,

  // --- actors / clients ---
  user: (
    <>
      <circle cx="12" cy="8" r="3.6" />
      <path d="M5.5 20c0-3.6 2.9-6.2 6.5-6.2S18.5 16.4 18.5 20" />
    </>
  ),
  browser: (
    <>
      <rect x="3" y="4" width="18" height="16" rx="2" />
      <path d="M3 9h18" />
      <circle cx="6" cy="6.5" r="0.7" fill="currentColor" stroke="none" />
      <circle cx="8.6" cy="6.5" r="0.7" fill="currentColor" stroke="none" />
    </>
  ),
  mobile: (
    <>
      <rect x="7" y="2.5" width="10" height="19" rx="2.5" />
      <path d="M10.5 18.5h3" />
    </>
  ),
  api: <path d="M9 8l-4 4 4 4M15 8l4 4-4 4" />,

  // --- compute / services ---
  globe: (
    <>
      <circle cx="12" cy="12" r="8.5" />
      <path d="M3.6 12h16.8" />
      <path d="M12 3.5c2.4 2.3 2.4 14.7 0 17M12 3.5c-2.4 2.3-2.4 14.7 0 17" />
    </>
  ),
  bolt: <path d="M13 2.5 4.5 13.5H11l-1 8 8.5-11H12l1-7.5z" />,
  hexnode: (
    <>
      <path d="M12 2.6l8.2 4.7v9.4L12 21.4 3.8 16.7V7.3z" />
      <circle cx="12" cy="12" r="2.4" />
    </>
  ),
  server: (
    <>
      <rect x="3" y="4" width="18" height="6.5" rx="1.5" />
      <rect x="3" y="13.5" width="18" height="6.5" rx="1.5" />
      <path d="M6.5 7.2h.01M6.5 16.7h.01" />
    </>
  ),

  // --- data / storage ---
  orbit: (
    <>
      <circle cx="12" cy="12" r="2.8" />
      <ellipse cx="12" cy="12" rx="10" ry="4.4" />
      <ellipse cx="12" cy="12" rx="10" ry="4.4" transform="rotate(60 12 12)" />
    </>
  ),
  boxes: (
    <>
      <rect x="3" y="3.5" width="7.5" height="7.5" rx="1.2" />
      <rect x="13.5" y="3.5" width="7.5" height="7.5" rx="1.2" />
      <rect x="8.25" y="13" width="7.5" height="7.5" rx="1.2" />
    </>
  ),
  relay: (
    <>
      <rect x="3" y="6" width="18" height="12" rx="2" />
      <path d="M3.6 7.2l8.4 6 8.4-6" />
    </>
  ),

  // --- identity / secrets ---
  idbadge: (
    <>
      <rect x="4.5" y="3" width="15" height="18" rx="2" />
      <path d="M9.5 3v2.2h5V3" />
      <circle cx="12" cy="10" r="2.3" />
      <path d="M8.3 16.5c0-2 1.7-3 3.7-3s3.7 1 3.7 3" />
    </>
  ),
  key: (
    <>
      <circle cx="7.5" cy="12" r="3.5" />
      <path d="M10.8 12H20M17 12v3.2M20 12v2.4" />
    </>
  ),
  shieldid: (
    <>
      <path d="M12 3l7 2.8v5.2c0 4.4-3 7.4-7 8.9-4-1.5-7-4.5-7-8.9V5.8z" />
      <circle cx="12" cy="10" r="1.9" />
      <path d="M8.8 15.4c0-1.5 1.4-2.3 3.2-2.3s3.2.8 3.2 2.3" />
    </>
  ),

  // --- network ---
  network: (
    <>
      <circle cx="12" cy="5" r="2.3" />
      <circle cx="5" cy="19" r="2.3" />
      <circle cx="19" cy="19" r="2.3" />
      <path d="M12 7.3 5.8 16.8M12 7.3l6.2 9.5M7.3 19h9.4" />
    </>
  ),
  grid: (
    <>
      <rect x="3" y="3" width="18" height="18" rx="2" />
      <path d="M3 9h18M3 15h18M9 3v18M15 3v18" />
    </>
  ),
  gateway: (
    <>
      <circle cx="12" cy="4.5" r="1.9" />
      <circle cx="5.5" cy="19" r="2.1" />
      <circle cx="18.5" cy="19" r="2.1" />
      <path d="M12 6.4v3.2M12 9.6 6.2 16.9M12 9.6l5.8 7.3" />
    </>
  ),
  plug: (
    <>
      <path d="M9 2.5v5M15 2.5v5" />
      <path d="M7 7.5h10v3.2a5 5 0 0 1-10 0z" />
      <path d="M12 15.7v5.8" />
    </>
  ),
};

/** Icon name per specialized stencil id; unlisted ids fall back to their base primitive. */
const STENCIL_ICON: Record<string, string> = {
  'human-actor': 'user',
  browser: 'browser',
  'mobile-app': 'mobile',
  'third-party-api': 'api',
  'azure-app-service': 'globe',
  'azure-function': 'bolt',
  'azure-aks': 'hexnode',
  'azure-vm': 'server',
  'azure-sql': 'database',
  'azure-cosmos': 'orbit',
  'azure-blob': 'boxes',
  'azure-service-bus': 'relay',
  'entra-id': 'idbadge',
  'azure-key-vault': 'key',
  'managed-identity': 'shieldid',
  'azure-vnet': 'network',
  'azure-subnet': 'grid',
  'app-gateway': 'gateway',
  'private-endpoint': 'plug',
};

const BASE_ICON: Record<DfdKind, string> = {
  process: 'cpu',
  datastore: 'database',
  external: 'monitor',
  boundary: 'boundary',
};

/**
 * Official Azure Architecture Icons per specialized stencil id (full-color brand SVGs, rendered as
 * <img> so they keep their gradients). Non-Azure stencils fall through to the line-icon set above.
 */
const AZURE_ICON: Record<string, string> = {
  'azure-app-service': appServiceUrl,
  'azure-function': functionUrl,
  'azure-aks': aksUrl,
  'azure-vm': vmUrl,
  'azure-sql': sqlUrl,
  'azure-cosmos': cosmosUrl,
  'azure-blob': blobUrl,
  'azure-service-bus': serviceBusUrl,
  'entra-id': entraIdUrl,
  'azure-key-vault': keyVaultUrl,
  'managed-identity': managedIdentityUrl,
  'azure-vnet': vnetUrl,
  'azure-subnet': subnetUrl,
  'app-gateway': appGatewayUrl,
  'private-endpoint': privateEndpointUrl,
};

/** Resolves a stencil id (or its base primitive) to an icon name. */
function iconName(id: string | undefined, base: DfdKind): string {
  return (id ? STENCIL_ICON[id] : undefined) ?? BASE_ICON[base] ?? 'cpu';
}

/**
 * Renders a stencil's icon: the official Azure SVG for Azure services (branded color), otherwise the
 * monochrome line icon colored by `currentColor`. `size` is the box edge in px.
 */
export function StencilIcon({ id, base, size = 18 }: { id?: string; base: DfdKind; size?: number }) {
  const azure = id ? AZURE_ICON[id] : undefined;
  if (azure) {
    return <img className="stencil-img" src={azure} width={size} height={size} alt="" draggable={false} />;
  }
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.75}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      {ICONS[iconName(id, base)]}
    </svg>
  );
}

/** Shared 24×24 line-icon frame (currentColor stroke, round joins) matching the stencil icon set. */
function LineIcon({ size, children }: { size: number; children: ReactNode }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.75}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      {children}
    </svg>
  );
}

/** Curved-arrow "undo" icon. */
export function UndoIcon({ size = 18 }: { size?: number }) {
  return (
    <LineIcon size={size}>
      <path d="M9 14 4 9l5-5" />
      <path d="M4 9h10.5a5.5 5.5 0 0 1 0 11H11" />
    </LineIcon>
  );
}

/** Curved-arrow "redo" icon (mirror of undo). */
export function RedoIcon({ size = 18 }: { size?: number }) {
  return (
    <LineIcon size={size}>
      <path d="m15 14 5-5-5-5" />
      <path d="M20 9H9.5a5.5 5.5 0 0 0 0 11H13" />
    </LineIcon>
  );
}

export function ShareIcon({ size = 18 }: { size?: number }) {
  return (
    <LineIcon size={size}>
      <circle cx="18" cy="5" r="3" />
      <circle cx="6" cy="12" r="3" />
      <circle cx="18" cy="19" r="3" />
      <path d="m8.6 10.5 6.8-4m-6.8 7 6.8 4" />
    </LineIcon>
  );
}
