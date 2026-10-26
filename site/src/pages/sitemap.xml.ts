import { siteData } from '../lib/load';
import { href } from '../lib/util';

export const prerender = true;

export function GET({ site }: { site?: URL }) {
  const paths = ['', 'gotchas/', 'lookups/', 'about/', ...siteData().entries.map((e) => `b/${e.slug}/`)];
  const urls = paths.map((p) => `  <url><loc>${new URL(href(p), site).href}</loc></url>`).join('\n');
  const xml = `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls}\n</urlset>\n`;
  return new Response(xml, { headers: { 'Content-Type': 'application/xml; charset=utf-8' } });
}
