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
COPY cmd/sandbox-control ./cmd/sandbox-control
COPY cmd/sandbox-host ./cmd/sandbox-host
COPY cmd/sandbox-host-bootstrap ./cmd/sandbox-host-bootstrap
# Composition binaries share internal packages. The sealed build context copies
# the reviewed module trees rather than maintaining a brittle package list.
COPY internal ./internal
COPY sandbox ./sandbox
COPY temporalpayload ./temporalpayload
COPY sdk ./sdk
RUN go mod verify
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -mod=readonly -trimpath -ldflags='-s -w' -o /out/runtime ./cmd/runtime
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -mod=readonly -trimpath -ldflags='-s -w' -o /out/egress-proxy ./cmd/egress-proxy
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -mod=readonly -trimpath -ldflags='-s -w' -o /out/agent-runtime-api ./cmd/agent-runtime-api
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -mod=readonly -trimpath -ldflags='-s -w' -o /out/sandbox-control ./cmd/sandbox-control
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -mod=readonly -trimpath -ldflags='-s -w' -o /out/sandbox-host ./cmd/sandbox-host
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -mod=readonly -trimpath -ldflags='-s -w' -o /out/sandbox-host-bootstrap ./cmd/sandbox-host-bootstrap

FROM gcr.io/distroless/static-debian12:nonroot@sha256:f5b485ea962d9bd1186b2f6b3a061191539b905b82ec395de78cbfae51f20e35
COPY --from=build /out/runtime /runtime
COPY --from=build /out/egress-proxy /egress-proxy
COPY --from=build /out/agent-runtime-api /agent-runtime-api
COPY --from=build /out/sandbox-control /sandbox-control
COPY --from=build /out/sandbox-host /sandbox-host
COPY --from=build /out/sandbox-host-bootstrap /sandbox-host-bootstrap
USER nonroot:nonroot
ENTRYPOINT ["/runtime"]
