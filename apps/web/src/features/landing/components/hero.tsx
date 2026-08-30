import { Button, ButtonLink } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Container } from "@/components/ui/container";
import { Surface } from "@/components/ui/surface";
import { landingContent } from "../content";

const { hero } = landingContent;

export function Hero() {
  return (
    <section className="py-16 sm:py-24">
      <Container>
        <div className="grid items-center gap-12 lg:grid-cols-2">
          <div>
            <Badge>{hero.eyebrow}</Badge>
            <h1 className="mt-6 font-display text-4xl leading-tight text-on-surface sm:text-5xl lg:text-6xl">
              {hero.heading}
            </h1>
            <p className="mt-6 max-w-prose text-lg text-on-surface-variant">{hero.body}</p>
            <div className="mt-10 flex flex-wrap items-center gap-4">
              <Button disabled aria-describedby="primary-action-note">
                {hero.primaryAction}
              </Button>
              <ButtonLink href={hero.secondaryAction.href}>{hero.secondaryAction.label}</ButtonLink>
            </div>
            <p id="primary-action-note" className="mt-4 text-sm text-on-surface-variant">
              {hero.primaryActionNote}
            </p>
          </div>
          <TonalStack />
        </div>
      </Container>
    </section>
  );
}

/* Decoration, and only that: three tonal steps, carrying no data and no claim. */
function TonalStack() {
  return (
    <div aria-hidden>
      <Surface tone="surface" className="p-4">
        <div className="rounded-card bg-surface-high p-4">
          <div className="aspect-video rounded-card bg-surface-highest" />
          <div className="mt-4 flex gap-3">
            <div className="h-3 w-24 rounded-pill bg-primary" />
            <div className="h-3 w-16 rounded-pill bg-tertiary" />
            <div className="h-3 w-10 rounded-pill bg-outline-strong" />
          </div>
        </div>
      </Surface>
    </div>
  );
}
