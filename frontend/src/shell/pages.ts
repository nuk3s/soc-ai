// ---------------------------------------------------------------------------
// The name of each page, for the breadcrumb and for a back link.
//
// One map, so the breadcrumb, the sidebar and a back link that names the page
// the analyst came from all say the same word. The nav said "Config" over a
// page the docs called "Settings", and "Operate" named a group and a page.
// ---------------------------------------------------------------------------

/** The guide, served beside the console under the same base path. */
export const GUIDE_URL = `${import.meta.env.BASE_URL}guide/`;

/** The breadcrumb of a path: the page, and the record on it when there is one. */
export interface Crumb {
  crumb: string;
  crumb2?: string;
}

/** The page a path belongs to, and the record it names. */
export function crumbFor(pathname: string): Crumb {
  const [, first = '', second] = pathname.split('/');
  const record = second ? decodeURIComponent(second) : undefined;
  switch (first) {
    case 'dashboard':
      return { crumb: 'Dashboard' };
    case 'alerts':
      return { crumb: 'Alerts' };
    case 'investigations':
      return { crumb: 'Investigations' };
    case 'investigation':
      return { crumb: 'Investigation', crumb2: record };
    case 'hunts':
      return record ? { crumb: 'Hunts', crumb2: record } : { crumb: 'Hunts' };
    // A lead lives on the Hunts page, so its breadcrumb starts there.
    case 'leads':
      return record ? { crumb: 'Hunts', crumb2: `Lead ${record}` } : { crumb: 'Hunts' };
    case 'hosts':
      return record ? { crumb: 'Hosts', crumb2: record } : { crumb: 'Hosts' };
    // The entity page shows an address the host list does not hold.
    case 'entity':
      return record ? { crumb: 'Hosts', crumb2: record } : { crumb: 'Hosts' };
    case 'notifications':
      return { crumb: 'Notifications' };
    case 'operate':
      return { crumb: 'Status' };
    case 'backtest':
      return { crumb: 'Backtest' };
    case 'runbooks':
      return { crumb: 'Runbooks' };
    case 'config':
      return { crumb: 'Settings' };
    default:
      return { crumb: '' };
  }
}

/** The words a back link uses for a path: "Alerts", "Hunt", "Lead 18". */
export function pageLabel(path: string): string {
  const pathname = path.split(/[?#]/, 1)[0];
  const { crumb, crumb2 } = crumbFor(pathname);
  if (pathname.startsWith('/leads/') && crumb2) return crumb2;
  if (pathname.startsWith('/hunts/')) return 'Hunt';
  if (pathname.startsWith('/hosts/') || pathname.startsWith('/entity/')) return 'Host';
  return crumb;
}
