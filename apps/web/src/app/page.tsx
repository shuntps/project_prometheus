import { Closing } from "@/features/landing/components/closing";
import { Hero } from "@/features/landing/components/hero";
import { Sections } from "@/features/landing/components/sections";
import { SiteFooter } from "@/features/landing/components/site-footer";
import { SiteHeader } from "@/features/landing/components/site-header";

export default function LandingPage() {
  return (
    <>
      <SiteHeader />
      <main id="main">
        <Hero />
        <Sections />
        <Closing />
      </main>
      <SiteFooter />
    </>
  );
}
