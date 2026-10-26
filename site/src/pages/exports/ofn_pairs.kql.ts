import { pairsKql } from '../../lib/derive';
import { siteData } from '../../lib/load';

export const prerender = true;

export function GET() {
  return new Response(pairsKql(siteData().pairs), { headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
}
