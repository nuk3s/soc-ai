import { Suspense } from 'react';

import { lazyWithReload } from '../lib/lazyWithReload';

/**
 * Explicit URL allow-list for links in agent output. Agent markdown is derived
 * from attacker-influenced data (payloads, hostnames, rule names), so link hrefs
 * are untrusted. Only http/https/mailto and scheme-less (relative/anchor) targets
 * pass; anything with another scheme (javascript:, data:, vbscript:, …) is dropped.
 * Pinning this in code means link safety no longer depends on react-markdown's
 * default urlTransform, which a library upgrade could silently change. The
 * scheme-detection matches react-markdown's own default: a ':' is only a scheme
 * delimiter when it precedes the first '/', '?', or '#'.
 */
export function safeUrl(url: string): string {
  // Protocol-relative ("//host/path") has no ':' at all, so it would otherwise
  // fall into the no-scheme "safe" branch below — but a browser resolves it
  // against the CURRENT scheme, so it still navigates (or, for an <img>, loads)
  // off-app to an attacker-controlled host, just without a visible scheme. The
  // app never needs one — same-origin paths already start with a single '/'.
  // Strip leading C0 controls/space first (a browser's URL parser does the
  // same) so a whitespace-padded "  //evil.example" can't dodge the check.
  if (url.replace(/^[\x00-\x20]+/, '').startsWith('//')) return '';
  const colon = url.indexOf(':');
  if (colon === -1) return url; // no scheme → relative/anchor, safe
  const firstSpecial = Math.min(
    ...['/', '?', '#'].map((c) => {
      const i = url.indexOf(c);
      return i === -1 ? Infinity : i;
    }),
  );
  if (colon > firstSpecial) return url; // ':' is part of the path, not a scheme
  const scheme = url.slice(0, colon).toLowerCase();
  return scheme === 'http' || scheme === 'https' || scheme === 'mailto' ? url : '';
}

// react-markdown (+ remark-gfm) is ~159 KB (48 KB gzipped). A static import
// here put that on the critical path of every chat-bearing route (Dashboard,
// Alerts, Investigation, InvestigationPage, HostDetail, HuntDetail, Runbooks):
// it had to download and evaluate before the route module ran, yet it renders
// nothing until a chat bubble actually holds assistant text. Load it lazily
// instead — the chunk detaches from all seven route graphs, and a bubble shows
// its raw text (the Suspense fallback) for the instant before the chunk lands.
// remark-gfm rides in the same async chunk (imported together here), so the
// table/strikethrough support never costs a second round-trip.
//
// lazyWithReload, not bare lazy: this is a NEW dynamic-import site, so after a
// deploy an already-open tab's first bubble-render would 404 the dead-hash
// chunk. lazyWithReload self-heals that with one in-place reload (the same
// protection every route import gets) instead of throwing to the screen-level
// error boundary.
const LazyMarkdown = lazyWithReload(async () => {
  const [{ default: ReactMarkdown }, { default: remarkGfm }] = await Promise.all([
    import('react-markdown'),
    import('remark-gfm'),
  ]);
  function RenderedMarkdown({ children }: { children: string }) {
    return (
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        urlTransform={safeUrl}
        components={{
          p: ({ children }) => <p className="mb-1.5 last:mb-0">{children}</p>,
          ul: ({ children }) => (
            <ul className="mb-1.5 ml-[18px] list-disc space-y-0.5 last:mb-0">{children}</ul>
          ),
          ol: ({ children }) => (
            <ol className="mb-1.5 ml-[18px] list-decimal space-y-0.5 last:mb-0">{children}</ol>
          ),
          li: ({ children }) => <li className="leading-[1.5]">{children}</li>,
          strong: ({ children }) => <strong className="font-semibold text-text">{children}</strong>,
          em: ({ children }) => <em className="italic">{children}</em>,
          code: ({ children }) => (
            <code className="rounded-[4px] bg-bg px-1 py-px font-mono text-[11.5px] text-mono-amber">
              {children}
            </code>
          ),
          pre: ({ children }) => (
            <pre className="mb-1.5 overflow-x-auto rounded-control border border-border bg-bg p-2 font-mono text-[11.5px] leading-[1.5] last:mb-0">
              {children}
            </pre>
          ),
          h1: ({ children }) => (
            <div className="mb-1 mt-2 text-[13px] font-semibold text-text first:mt-0">{children}</div>
          ),
          h2: ({ children }) => (
            <div className="mb-1 mt-2 text-[13px] font-semibold text-text first:mt-0">{children}</div>
          ),
          h3: ({ children }) => (
            <div className="mb-1 mt-2 text-[12.5px] font-semibold text-text-2 first:mt-0">{children}</div>
          ),
          a: ({ children, href }) => (
            <a href={href} target="_blank" rel="noopener noreferrer" className="text-accent underline">
              {children}
            </a>
          ),
          // Tables always get an overflow-x-auto wrapper: at narrow widths (the
          // 400px chat dock) a multi-column table scrolls horizontally instead of
          // crushing; on wide surfaces the wrapper is inert (no scrollbar when it
          // fits). Header cells stay on one line so columns can't collapse below
          // their label width — that's what forces the scroll instead of the crush.
          table: ({ children }) => (
            <div className="mb-1.5 overflow-x-auto last:mb-0">
              <table className="w-full border-collapse text-[12px]">{children}</table>
            </div>
          ),
          th: ({ children }) => (
            <th className="whitespace-nowrap border border-border px-2 py-1 text-left font-semibold">
              {children}
            </th>
          ),
          td: ({ children }) => <td className="border border-border px-2 py-1">{children}</td>,
        }}
      >
        {children}
      </ReactMarkdown>
    );
  }
  return { default: RenderedMarkdown };
});

/** Renders assistant Markdown into the dark theme — tight spacing for chat. */
export function Markdown({ children }: { children: string }) {
  return (
    // Fallback = the raw text: a bubble shows plaintext for the instant before
    // the react-markdown chunk loads, never a blank or a spinner.
    <Suspense fallback={<span className="whitespace-pre-wrap">{children}</span>}>
      <LazyMarkdown>{children}</LazyMarkdown>
    </Suspense>
  );
}
