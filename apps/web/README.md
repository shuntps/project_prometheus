# Web application

The public web surface. It is a Next.js App Router application; the Go service
under `services/core-api` is the sole authority for authentication and
authorisation.

During server rendering the opaque session cookie can reach Next.js, and it can
be relayed to the API. Next.js does not decode it, does not validate it, creates
no session, decides no role or permission, does not log it and does not place it
in a shared cache. Any identity a page displays comes from an authorised
response of the Go API.

## Structure

```
src/
  app/          route segments and layouts, composition only
  components/
    ui/         neutral design-system primitives
  config/       validated application configuration
  features/
    landing/
      components/   components belonging to this surface alone
      content.ts    every word this surface displays
  styles/       the theme, as CSS custom properties
tests/
  e2e/          Playwright, a browser against the production output
  policy/       Vitest, invariants of the sources and of this structure
  support/      fixtures shared by the suites
  unit/         Vitest, functions with no framework around them
```

## Which way imports point

```
app  →  features  →  components/ui  →  config
```

- `app` may import `features`, `components/ui` and `config`.
- a feature may import `components/ui` and `config`.
- `components/ui` may import neither `features` nor `app`, and holds no domain logic.
- `config` imports no user interface.

ESLint enforces all three restrictions; a violation fails `lint`, not review.

A new domain goes in `features/<domain>`, not into `app` or `components`.

`components/ui` holds design-system primitives, and the criterion is semantic
rather than a headcount: no knowledge of a domain or of a feature, a generic and
stable visual API, and a shape the design system already defines. Today
`landing` is their only consumer. A component carrying domain meaning stays in
its feature; it is never moved up on speculation.

There are no `services`, `controllers`, `modules`, `utils` or `lib` directories,
and no barrel file re-exporting the application.

## Commands

Run from this directory, or from the repository root through
`pnpm --filter @app/web <script>`.

| Purpose            | Command                                      |
| ------------------ | -------------------------------------------- |
| Development server | `pnpm dev`                                   |
| Production build   | `pnpm build`                                 |
| Serve a build      | `pnpm start`                                 |
| Formatting         | `pnpm format` (`pnpm format:write` to apply) |
| Lint               | `pnpm lint`                                  |
| Types              | `pnpm typecheck`                             |
| Unit tests         | `pnpm test:unit`                             |
| Policy tests       | `pnpm test:policy`                           |
| Browser tests      | `pnpm test:e2e`                              |
| Every suite        | `pnpm test`                                  |

`test:e2e` builds the application once and drives the standalone output, which
is what the image runs. The other suites start nothing.

## Configuration

| Variable                   | Required          | Meaning                                                                                                                                                                                                                                                                                                                         |
| -------------------------- | ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `SITE_NAME`                | Yes in production | The public name. Read on the server, then deliberately rendered into the HTML — the document title, the header and the footer. It comes from configuration rather than from a literal in a component. It has no production default, is trimmed, is bounded at 64 Unicode code points and refuses control and format characters. |
| `CORE_API_INTERNAL_ORIGIN` | No                | Server-only. When set, `/api/*` is rewritten to this origin for a local topology; it is never rendered and never sent to the browser. It must be a bare `http`/`https` origin with no credentials, path, query or fragment. Unset means no rewrite is installed and nothing is required.                                        |

Neither is declared as a client environment variable: no `NEXT_PUBLIC_` name
carries either, so neither is inlined into the browser bundle. That is a
separate question from what a page displays — the public name is meant to be
seen, while the internal origin never leaves the server. In production the edge
routes `/api` to the Go service and everything else here, so the browser only
ever sees one origin.

`.env.example` is a versioned template, not a file Next.js loads. For a direct
local run, copy it once from the repository root:

```bash
cp apps/web/.env.example apps/web/.env.local
```

Docker Compose already sets both values for the `web` container — it supplies
`http://core-api:8080` as the internal origin — so that copy matters mainly when
this application is run on its own.

## Image

```bash
docker build -f apps/web/Dockerfile --build-arg SITE_NAME='<name>' -t web:local .
```

Run this from the repository root: the build context is the workspace root, and
`Dockerfile.dockerignore` withholds everything the build does not need.
