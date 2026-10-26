import { ofnJson } from '../../lib/derive';
import { siteData } from '../../lib/load';

export const prerender = true;

export function GET() {
  return new Response(ofnJson(siteData().entries), { headers: { 'Content-Type': 'application/json; charset=utf-8' } });
}
