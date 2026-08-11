# One production image carries the reviewed composition binaries. The Stack
# selects a trust-scoped command; it never changes the image contents at runtime.
FROM --platform=$BUILDPLATFORM golang:1.26.0-alpine3.23@sha256:d4c4845f5d60c6a974c6000ce58ae079328d03ab7f721a0734277e69905473e5 AS build

ARG TARGETOS
ARG TARGETARCH

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/runtime ./cmd/runtime
COPY cmd/egress-proxy ./cmd/egress-proxy
COPY cmd/agent-runtime-api ./cmd/agent-runtime-api
COPY internal/roles ./internal/roles
COPY internal/egressproxy ./internal/egressproxy
COPY internal/runtimeapi ./internal/runtimeapi
COPY internal/runtimeapiprocess ./internal/runtimeapiprocess
COPY internal/runtimecontent ./internal/runtimecontent
COPY internal/runtimestate ./internal/runtimestate
COPY internal/runtimepostgres ./internal/runtimepostgres
COPY internal/identity ./internal/identity
RUN go mod verify
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -mod=readonly -trimpath -ldflags='-s -w' -o /out/runtime ./cmd/runtime
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -mod=readonly -trimpath -ldflags='-s -w' -o /out/egress-proxy ./cmd/egress-proxy
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -mod=readonly -trimpath -ldflags='-s -w' -o /out/agent-runtime-api ./cmd/agent-runtime-api

FROM gcr.io/distroless/static-debian12:nonroot@sha256:f5b485ea962d9bd1186b2f6b3a061191539b905b82ec395de78cbfae51f20e35
COPY --from=build /out/runtime /runtime
COPY --from=build /out/egress-proxy /egress-proxy
COPY --from=build /out/agent-runtime-api /agent-runtime-api
USER nonroot:nonroot
ENTRYPOINT ["/runtime"]
