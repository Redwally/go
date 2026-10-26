FROM golang:1.22-alpine AS builder

WORKDIR /app
COPY main.go .
RUN go mod init proxy && CGO_ENABLED=0 GOOS=linux go build -o proxy main.go

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/proxy .

EXPOSE 25565

CMD ["./proxy"]