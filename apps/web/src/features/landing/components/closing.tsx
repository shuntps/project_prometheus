import { Container } from "@/components/ui/container";
import { Surface } from "@/components/ui/surface";
import { landingContent } from "../content";

const { closing } = landingContent;

export function Closing() {
  return (
    <section className="py-12 sm:py-16">
      <Container>
        <Surface tone="highest" className="p-8 text-center sm:p-12">
          <h2 className="font-display text-3xl text-on-surface sm:text-4xl">{closing.heading}</h2>
          <p className="mx-auto mt-4 max-w-prose text-lg text-on-surface-variant">{closing.body}</p>
        </Surface>
      </Container>
    </section>
  );
}
