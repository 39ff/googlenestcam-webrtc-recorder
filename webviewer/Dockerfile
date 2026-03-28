FROM golang:1.24.3 AS builder
WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY webviewer/ ./webviewer/

RUN CGO_ENABLED=0 go build -o /app/bin/webviewer ./webviewer

FROM gcr.io/distroless/static-debian12
COPY --from=builder /app/bin/webviewer /usr/local/bin/webviewer

ENTRYPOINT ["/usr/local/bin/webviewer"]
CMD ["-dir", "/recordings", "-addr", ":8080"]
