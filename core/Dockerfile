FROM golang:1.24-alpine AS builder
RUN apk add --no-cache gcc musl-dev
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o sentery-proxy .

FROM alpine:latest
RUN apk add --no-cache ca-certificates sqlite
WORKDIR /root/
COPY --from=builder /app/sentery-proxy .
EXPOSE 8080
CMD ["./sentery-proxy"]
