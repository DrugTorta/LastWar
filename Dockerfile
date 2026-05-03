FROM golang:1.21-alpine AS builder
RUN apk add --no-cache gcc musl-dev
WORKDIR /app
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go build -o server .

FROM alpine:latest
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /app/server .
COPY --from=builder /app/static/ ./static/
COPY --from=builder /app/mods/ ./mods/
# Создаем директорию для Railway Volume
RUN mkdir -p /data && chmod 777 /data
# Создаем локальную директорию для разработки
RUN mkdir -p /app/database
EXPOSE 8080
CMD ["./server"]
