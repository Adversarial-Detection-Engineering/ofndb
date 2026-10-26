import { ofnJson } from '../../lib/derive';
import { siteData } from '../../lib/load';
import { href } from '../../lib/util';

export const prerender = true;

export function GET({ site }: { site?: URL }) {
  const body = ofnJson(siteData().entries, (slug) => new URL(href(`b/${slug}/`), site).href);
  return new Response(body, { headers: { 'Content-Type': 'application/json; charset=utf-8' } });
}
