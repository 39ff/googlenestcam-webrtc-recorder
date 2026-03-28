FROM golang:1.24.3 AS builder
WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY webviewer/ ./webviewer/

RUN CGO_ENABLED=0 go build -o webviewer ./webviewer

FROM gcr.io/distroless/static-debian12
COPY --from=builder /app/webviewer /usr/local/bin/webviewer

ENTRYPOINT ["webviewer"]
CMD ["-dir", "/recordings", "-addr", ":8080"]
