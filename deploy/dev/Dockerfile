FROM golang:1.26.0-alpine3.23@sha256:d4c4845f5d60c6a974c6000ce58ae079328d03ab7f721a0734277e69905473e5 AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/dev-role ./cmd/dev-role
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags='-s -w' -o /out/agent-runtime-dev-role ./cmd/dev-role

FROM gcr.io/distroless/static-debian12:nonroot@sha256:f5b485ea962d9bd1186b2f6b3a061191539b905b82ec395de78cbfae51f20e35
COPY --from=build /out/agent-runtime-dev-role /agent-runtime-dev-role
USER nonroot:nonroot
ENTRYPOINT ["/agent-runtime-dev-role"]
