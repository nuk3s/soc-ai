import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';

/** Renders assistant Markdown into the dark theme — tight spacing for chat. */
export function Markdown({ children }: { children: string }) {
  return (
    <ReactMarkdown
      remarkPlugins={[remarkGfm]}
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
          <a href={href} target="_blank" rel="noreferrer" className="text-accent underline">
            {children}
          </a>
        ),
        table: ({ children }) => (
          <table className="mb-1.5 w-full border-collapse text-[12px] last:mb-0">{children}</table>
        ),
        th: ({ children }) => (
          <th className="border border-border px-2 py-1 text-left font-semibold">{children}</th>
        ),
        td: ({ children }) => <td className="border border-border px-2 py-1">{children}</td>,
      }}
    >
      {children}
    </ReactMarkdown>
  );
}
