import type { Metadata } from "next";

import { Container } from "@/components/ui/container";
import { Surface } from "@/components/ui/surface";
import { siteName } from "@/config/site";
import { VerificationPanel } from "@/features/registration/components/verification-panel";
import { registrationContent } from "@/features/registration/content";

const { verify: copy } = registrationContent;

export const metadata: Metadata = {
  title: `${copy.title} · ${siteName}`,
};

/* The token travels in the fragment, which the browser does not send, so this
   server never receives it. Nothing here reads a parameter, and the same
   document is rendered for every visitor. */
export default function VerifyEmailPage() {
  return (
    <main id="main" className="py-16 sm:py-24">
      <Container>
        <Surface tone="surface" className="mx-auto max-w-md p-8 sm:p-10">
          <h1 className="font-display text-3xl text-on-surface">{copy.title}</h1>
          <div className="mt-8">
            <VerificationPanel />
          </div>
        </Surface>
      </Container>
    </main>
  );
}
