import { ofnCsv } from '../../lib/derive';
import { siteData } from '../../lib/load';

export const prerender = true;

export function GET() {
  return new Response(ofnCsv(siteData().entries), { headers: { 'Content-Type': 'text/csv; charset=utf-8' } });
}
