import { Container } from "@/components/ui/container";
import { Surface } from "@/components/ui/surface";
import { landingContent } from "../content";

export function Sections() {
  return (
    <>
      {landingContent.sections.map((section) => (
        <section key={section.id} id={section.id} className="scroll-mt-8 py-12 sm:py-16">
          <Container>
            <Surface tone="surface" className="p-6 sm:p-10">
              <h2 className="font-display text-3xl text-on-surface sm:text-4xl">
                {section.heading}
              </h2>
              <p className="mt-4 max-w-prose text-lg text-on-surface-variant">{section.body}</p>
              <ul className="mt-8 grid gap-4 sm:grid-cols-3">
                {section.points.map((point) => (
                  <li key={point} className="rounded-card bg-surface-high p-5 text-on-surface">
                    {point}
                  </li>
                ))}
              </ul>
            </Surface>
          </Container>
        </section>
      ))}
    </>
  );
}
