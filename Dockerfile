FROM golang:1.25.5-alpine AS builder

RUN apk add --no-cache gcc musl-dev

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=1 go build -ldflags="-w -s -extldflags '-static'" -o /app/sso ./cmd/sso/main.go

FROM alpine:latest

WORKDIR /app

COPY --from=builder /app/sso .

EXPOSE 1337
CMD ["./sso"]
