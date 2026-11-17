// ---------------------------------------------------------------------------
// The published docs site: the console guide, the release notes and the doc
// sections the doctor names.
//
// The console served a guide under /app/guide/ that a build copies from
// frontend/public/guide/. That folder is not in the repository, and on the
// production console of 2026-11-12 it held the 1.5.0 release note under a
// 1.6.0 console. The docs site builds docs/ of the repository with MkDocs
// (mkdocs.yml), so the guide there is the current one.
// ---------------------------------------------------------------------------

/** The root of the docs site. mkdocs.yml `site_url`. */
export const DOCS_SITE = 'https://nuk3s.github.io/soc-ai/';

/** The console guide, docs/WEBUI_GUIDE.md on the docs site. */
export const CONSOLE_GUIDE_URL = `${DOCS_SITE}WEBUI_GUIDE/`;

/** The anchor MkDocs writes for a heading: lowercase, words joined by "-". */
export function headingAnchor(heading: string): string {
  return heading
    .toLowerCase()
    .replace(/[^a-z0-9\s-]/g, '')
    .trim()
    .replace(/\s+/g, '-');
}

/** The page of a repository doc on the docs site: "docs/DOCKER.md" reads
 *  "<site>/DOCKER/", with the anchor of a heading when one is given. */
export function docUrl(path: string, heading?: string): string {
  const page = path.replace(/^docs\//, '').replace(/\.md$/, '');
  const base = page === 'index' ? DOCS_SITE : `${DOCS_SITE}${page}/`;
  return heading ? `${base}#${headingAnchor(heading)}` : base;
}

/** The release notes of one version: "1.6.0" reads "<site>/releases/1.6.0/".
 *  A build after a tag carries a suffix ("1.6.0+abc"), and the notes of its
 *  release are the ones to read. With no version, the changelog. */
export function releaseNotesUrl(version: string | null | undefined): string {
  const m = (version ?? '').match(/^v?(\d+\.\d+\.\d+)/);
  return m ? `${DOCS_SITE}releases/${m[1]}/` : `${DOCS_SITE}project/changelog/`;
}
