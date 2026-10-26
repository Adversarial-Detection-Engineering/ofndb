import { pairsCsv } from '../../lib/derive';
import { siteData } from '../../lib/load';

export const prerender = true;

export function GET() {
  return new Response(pairsCsv(siteData().pairs), { headers: { 'Content-Type': 'text/csv; charset=utf-8' } });
}
