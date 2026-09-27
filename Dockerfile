FROM golang:1.25.7-alpine AS builder
WORKDIR /app

# The api module is required through a replace directive, so its manifest has
# to be present before `go mod download` — otherwise the download fails on a
# replacement target that does not exist yet. Copying only the manifests keeps
# the dependency layer cached across source changes.
COPY go.mod go.sum ./
COPY api/go.mod api/go.sum ./api/
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o sso ./cmd/sso

FROM alpine:3.21
RUN apk --no-cache add ca-certificates tzdata \
    && adduser -D -u 10001 app
WORKDIR /app

COPY --from=builder /app/sso .
COPY --from=builder /app/config ./config

# Nothing here needs root, and the container publishes a network port.
USER app

CMD ["./sso"]
