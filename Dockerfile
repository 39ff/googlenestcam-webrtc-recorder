# ---------- 1st stage : build ----------
FROM golang:1.24.3 AS builder
WORKDIR /app

# Go modules
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -o recorder .

# ---------- 2nd stage : runtime ----------
FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends ffmpeg tzdata ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
RUN mkdir "/app/mp4"
COPY --from=builder /app/recorder /usr/local/bin/recorder
COPY DejaVuSansMono.ttf /usr/share/DejaVuSansMono.ttf

ENTRYPOINT ["recorder"]
CMD ["-config", "/config/config.yaml"]
