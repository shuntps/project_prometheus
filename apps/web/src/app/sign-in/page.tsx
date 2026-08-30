import type { Metadata } from "next";

import { Container } from "@/components/ui/container";
import { Surface } from "@/components/ui/surface";
import { siteName } from "@/config/site";
import { SignInForm } from "@/features/session/components/sign-in-form";
import { sessionContent } from "@/features/session/content";

export const metadata: Metadata = {
  title: `${sessionContent.signIn.title} · ${siteName}`,
};

export default function SignInPage() {
  return (
    <main id="main" className="py-16 sm:py-24">
      <Container>
        <Surface tone="surface" className="mx-auto max-w-md p-8 sm:p-10">
          <h1 className="font-display text-3xl text-on-surface">{sessionContent.signIn.title}</h1>
          <p className="mt-4 text-on-surface-variant">{sessionContent.signIn.intro}</p>
          <div className="mt-8">
            <SignInForm />
          </div>
        </Surface>
      </Container>
    </main>
  );
}
