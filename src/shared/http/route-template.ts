import type { RouteParams } from './route-policy';

function safeDecode(segment: string): string {
  try {
    return decodeURIComponent(segment);
  } catch {
    return segment;
  }
}

/**
 * Low-cardinality route name for logs: the path with each path-param value replaced by its name,
 * e.g. `/api/v1/admin/processes/3f…/approvals` → `/api/v1/admin/processes/[processId]/approvals`.
 */
export function routeTemplate(pathname: string, params: RouteParams): string {
  const nameByValue = new Map<string, string>();
  for (const [name, value] of Object.entries(params)) {
    if (typeof value === 'string') nameByValue.set(value, `[${name}]`);
  }
  if (nameByValue.size === 0) return pathname;
  return pathname
    .split('/')
    .map((segment) => nameByValue.get(safeDecode(segment)) ?? segment)
    .join('/');
}
