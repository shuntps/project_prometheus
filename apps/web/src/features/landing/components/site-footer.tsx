import { Container } from "@/components/ui/container";
import { siteName } from "@/config/site";
import { landingContent } from "../content";

export function SiteFooter() {
  return (
    <footer className="border-t border-outline py-10">
      <Container>
        <p className="text-sm text-on-surface-variant">
          <span className="font-display text-base text-on-surface">{siteName}</span>
          <span className="mx-2">·</span>
          {landingContent.footer.note}
        </p>
      </Container>
    </footer>
  );
}
