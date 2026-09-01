import type { Metadata } from "next";
import Link from "next/link";

import { Container } from "@/components/ui/container";
import { Surface } from "@/components/ui/surface";
import { siteName } from "@/config/site";
import { RegistrationForm } from "@/features/registration/components/registration-form";
import { registrationContent } from "@/features/registration/content";

const { register: copy } = registrationContent;

export const metadata: Metadata = {
  title: `${copy.title} · ${siteName}`,
};

export default function RegisterPage() {
  return (
    <main id="main" className="py-16 sm:py-24">
      <Container>
        <Surface tone="surface" className="mx-auto max-w-md p-8 sm:p-10">
          <h1 className="font-display text-3xl text-on-surface">{copy.title}</h1>
          <p className="mt-4 text-on-surface-variant">{copy.intro}</p>
          <div className="mt-8">
            <RegistrationForm />
          </div>
          <p className="mt-8 text-sm text-on-surface-variant">
            {copy.signInPrompt}{" "}
            <Link
              href="/sign-in"
              className="rounded-pill text-on-surface underline underline-offset-4 transition-colors ease-standard duration-(--motion-duration) hover:text-primary"
            >
              {copy.signIn}
            </Link>
          </p>
        </Surface>
      </Container>
    </main>
  );
}
