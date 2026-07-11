import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';

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

/** Renders assistant Markdown into the dark theme — tight spacing for chat. */
export function Markdown({ children }: { children: string }) {
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
