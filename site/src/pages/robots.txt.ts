import { href } from '../lib/util';

export const prerender = true;

export function GET({ site }: { site?: URL }) {
  const body = `User-agent: *\nAllow: /\n\nSitemap: ${new URL(href('sitemap.xml'), site).href}\n`;
  return new Response(body, { headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
}
