import type { ReactNode } from 'react';
import { AskPanel, AskSocAiButton } from '../components/AskPanel';
import { ChatProvider, type ChatScope, useChatScope } from '../lib/chatScope';
import { ShellProvider } from '../shell/ShellContext';

/**
 * The shell's chat parts around a screen under test: the provider, the top
 * bar's Ask soc-ai button and the panel. A screen rendered alone has none of
 * them, because the shell mounts them once for every page. Render it inside a
 * router: the panel's hunt card navigates.
 */
export function WithChat({
  children,
  generalEnabled = true,
}: {
  children: ReactNode;
  generalEnabled?: boolean;
}) {
  return (
    <ShellProvider>
      <ChatProvider generalEnabled={generalEnabled}>
        <div data-testid="topbar">
          <AskSocAiButton />
        </div>
        {children}
        <AskPanel />
      </ChatProvider>
    </ShellProvider>
  );
}

/** A page that shows one object and claims the panel for it. */
export function ScopedPage({ scope, children }: { scope: ChatScope; children?: ReactNode }) {
  useChatScope({ scope });
  return <div data-testid={`page-${scope.kind}`}>{children}</div>;
}
