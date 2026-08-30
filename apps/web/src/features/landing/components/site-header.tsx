import type { ReactNode } from "react";

import { siteName } from "@/config/site";
import { Container } from "@/components/ui/container";
import { landingContent } from "../content";

/* accountAction is a neutral slot: this feature knows nothing of what fills it. */
export function SiteHeader({ accountAction }: { accountAction?: ReactNode }) {
  return (
    <header className="border-b border-outline">
      <Container>
        <div className="flex flex-wrap items-center gap-x-8 gap-y-3 py-5">
          <span className="font-display text-xl text-on-surface">{siteName}</span>
          <nav aria-label="Sections of this page">
            <ul className="flex flex-wrap gap-x-6 gap-y-2">
              {landingContent.navigation.map((item) => (
                <li key={item.href}>
                  <a
                    href={item.href}
                    className="rounded-pill text-on-surface-variant transition-colors ease-standard duration-(--motion-duration) hover:text-on-surface"
                  >
                    {item.label}
                  </a>
                </li>
              ))}
            </ul>
          </nav>
          {accountAction !== undefined && <div className="ml-auto">{accountAction}</div>}
        </div>
      </Container>
    </header>
  );
}
