# syntax=docker/dockerfile:1@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32

FROM golang:1.27.1-alpine@sha256:cf6fca6641884b8433441b2b0652976f975e1d0fdd26d177eaaf8596087f3125 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/core-api ./cmd/api
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/core-api-migrate ./cmd/migrate

# Development only: the build stage already holds the toolchain and the module
# cache, so this adds a command rather than a second image definition. The binary
# replaces the shell, so the service itself is what receives SIGTERM.
FROM build AS development
EXPOSE 8080
CMD ["sh", "-c", "go build -o /tmp/core-api ./cmd/api && exec /tmp/core-api"]

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
WORKDIR /
COPY --from=build /out/core-api /core-api
# The migration binary ships alongside the service so a deployment can run it as
# its own step. The entrypoint is unchanged: starting the service migrates nothing.
COPY --from=build /out/core-api-migrate /core-api-migrate
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/core-api"]
